/*
 * ACMICPC problem online judger Sabo
 * Copyright (C) 2016  zchao1995@gmail.com(Zhang Chao)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.  * * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sabo_core.h"


typedef struct {
    const char *first;
    int second;
} sabo_sofile;


int sabo_syscall[SABO_BUFFER_SIZE];

int sabo_syscall_whitelist[] = {0, 1, 2, 3, 5, 9, 10, 11, 12, 21, 59, 89, 158, 231};

sabo_sofile sabo_sofile_whitelist[] = {

    { "ld.so.cache"    , O_RDONLY | O_CLOEXEC } ,
    { "libstdc++.so.6" , O_RDONLY | O_CLOEXEC } ,
    { "libc.so.6"      , O_RDONLY | O_CLOEXEC } ,
    { "libm.so.6"      , O_RDONLY | O_CLOEXEC } ,
    { "libgcc_s.so.1"  , O_RDONLY | O_CLOEXEC } ,
};


int check_file(const char *file_name, int mode);
static void sabo_core_run(sabo_run_config *config, sabo_result_info *info);
static void sabo_core_init(void);
static void sabo_set_limit(const sabo_run_config *config);
static void sabo_child_run(const sabo_run_config *config, int in_spj_run);
static void sabo_monitor_run(pid_t child, const sabo_run_config *config, sabo_result_info *resinfo, int in_spj_run);
static void sabo_work_spj(const sabo_run_config *config, sabo_result_info *res);
static void sabo_kill(pid_t child);
static int sabo_check_accessfile(const char * filepath, int flag);
static int sabo_hack_open_file(struct user_regs_struct *reg, pid_t child);
static unsigned int sabo_get_process_runtime(const struct rusage *runinfo);
static unsigned int sabo_get_process_runmem(const struct rusage *runinfo, int use_sandbox, pid_t child);
static unsigned int sabo_get_proc_status(const char *item, pid_t pid);
PyMODINIT_FUNC PyInit_sabo_core(void);
static PyObject* py_run(PyObject *self, PyObject *args);
char* process_arg(PyObject *arg);


static void
sabo_core_init()
{
    int i;
    int count = sizeof(sabo_syscall_whitelist) / sizeof(int);

    memset(sabo_syscall, SABO_FORBIDDEN, sizeof(sabo_syscall));
    for (i = 0; i < count; ++i) {
        int call_num = sabo_syscall_whitelist[i];
        if (call_num >= SABO_BUFFER_SIZE) {
            continue;
        }
        sabo_syscall[call_num] = SABO_ALLOWED;
    }
}


/*
 * This function is used to check the file whether is allowed to open when the
 * child process called the open system call, if the file is not in the
 * file_white_list, user solution will be judged by MC(malicious code)
 */
static int
sabo_check_accessfile(const char * filepath, int flag)
{
    int i;
    const char *namepath = NULL;
    const char *temp = filepath;
    for (; *temp != '\0'; temp++) {
        if (*temp == '/') {
            namepath = temp + 1;
        }
    }

    if (namepath && *namepath != '\0') {
        filepath = namepath;
    }

    int count = sizeof(sabo_sofile_whitelist) / sizeof(sabo_sofile);

    if (filepath == NULL) {
        return SABO_ALLOWED;
    }
    for (i = 0; i < count; ++i) {
        if (!strcmp(filepath, sabo_sofile_whitelist[i].first) &&
            (flag & sabo_sofile_whitelist[i].second) == sabo_sofile_whitelist[i].second) {
            return SABO_ALLOWED;
        }
    }
    /* sabo_error_log(LOG_WARN, "file %s, not in whitelist", filepath); */
    return SABO_FORBIDDEN;
}


static unsigned int
sabo_get_proc_status(const char *item, pid_t pid)
{
    static int last_use = 0;
    char name[NAME_MAX];
    snprintf(name, sizeof(name), "/proc/%d/status", pid);
    FILE *p = fopen(name, "r");
    if (p == NULL) {
        return last_use;
    }

    unsigned int res = 0;
    int itemlen = strlen(item);
    while (fgets(name, NAME_MAX - 1, p)) {
        if (strncmp(item, name, itemlen) == 0) {
            sscanf(name + itemlen + 1, "%d", &res);
            break;
        }
    }

    fclose(p);
    last_use = res;
    return res;
}


/*
 * this function is used to get the filepath and flag, reference:
 * https://github.com/lodevil/Lo-runner
 * if long is 4 bytes, 4 char
 * if long is 8 bytes, 8 char
 * FIXME: this logic need to improve
 */
static int
sabo_hack_open_file(struct user_regs_struct *reg, pid_t child)
{
    if (reg == NULL) {
        /* sabo_error_log(LOG_ERR, "function: sabo_hack_open_file, arg: reg null"); */
        return TRUE;
    }

    long file_temp[NAME_MAX];
    int i;
    int j;

    for (i = 0; i < NAME_MAX; ++i) {
        const char * test;
        long t = ptrace(PTRACE_PEEKDATA, child, REG_ARG_1(reg) + i * sizeof(long), NULL);

        file_temp[i] = t;
        test = (const char*)&file_temp[i];
        int flag = FALSE;
        for (j = 0; j < (int)sizeof(long); ++j) {
            if (!test[j]) {
                file_temp[NAME_MAX - 1] = 0;
                flag = TRUE;
                break;
            }
        }

        if (flag) {
            break;
        }
    }

    return sabo_check_accessfile((const char*)file_temp, REG_ARG_2(reg));
}


static unsigned int
sabo_get_process_runtime(const struct rusage *runinfo)
{
    /*
     * Get the running time
     * time = cpu time + user time
     */

    unsigned int time_used;
    time_used = runinfo->ru_utime.tv_sec * 1000 + runinfo->ru_utime.tv_usec / 1000;
    time_used += runinfo->ru_stime.tv_sec * 1000 + runinfo->ru_stime.tv_usec / 1000;

    return time_used;
}


static unsigned int
sabo_get_process_runmem(const struct rusage *runinfo, int use_sandbox, pid_t child)
{
    /*
     * Get the used memory
     * ru_maxrss maybe the result is larger than the real usage
     * about ru_maxrss:
     * This is the maximum resident set size used (in kilobytes).
     * For RUSAGE_CHILDREN, this is the resident set size of the
     * largest child, not the maximum resident set
     * size of the process tree
     */

    if (!use_sandbox) {
        /* for java */
        return runinfo->ru_minflt * getpagesize();
    } else {
        return sabo_get_proc_status("VmPeak:", child);
    }
}


static void
sabo_kill(pid_t child)
{
    kill(child, SIGKILL);
    wait(&child);
}


static void
sabo_monitor_run(pid_t child, const sabo_run_config *config, sabo_result_info *resinfo, int in_spj_run)
{
    int runstat;
    struct rusage runinfo;
    int judge_flag = SABO_UNKNOWN;
    int memory_used;
    int use_sandbox = config->use_sandbox;
    int time_used;
    long long syscall;
    struct user_regs_struct reg;
    time_used = -1;

    for ( ; ; ) {
        /* block the monitor process */
        wait4(child, &runstat, 0, &runinfo);
        memory_used = sabo_get_process_runmem(&runinfo, use_sandbox, child);
        if (memory_used == -1) {
            judge_flag = SABO_SYSERR;
            time_used = 0;
            memory_used = 0;
            sabo_kill(child);
            break;
        }

        time_used = sabo_get_process_runtime(&runinfo);

        if (!in_spj_run && time_used > config->time_limits) {
            sabo_kill(child);
            judge_flag = 2;
            break;
        }

        if (!in_spj_run && memory_used > config->memory_limits) {
            sabo_kill(child);
            judge_flag = 3;
            break;
        }

        if (WIFEXITED(runstat)) { /* if the child process exit */
            judge_flag = SABO_AC; /* Note: this AC just stand that the user program is run successfully */
            if (in_spj_run) {
                judge_flag = WEXITSTATUS(runstat);
            }
            break;
        } else if (WIFSTOPPED(runstat)) {
            if (in_spj_run) {
                /* not limit the spj, supporter need to confirm it */
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                continue;
            }

            int signal = WSTOPSIG(runstat);
            if (signal == SIGFPE) {
                /* Float number exeption, always is divided by zero */
                judge_flag = SABO_RE_DBZ;
                sabo_kill(child);
                break;
            } else if (signal == SIGSEGV) {
                /* Segment Fault*/
                judge_flag = SABO_RE;
                sabo_kill(child);
                break;
            } else if (signal == SIGALRM) {
                /* Time Limit Exceed CPU TIME or USER TIME */
                judge_flag = SABO_TLE;
                sabo_kill(child);
                break;
            } else if (signal == SIGTRAP) {
                if (!use_sandbox) {
                    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                    continue;
                }

                /* get the reg info */
                ptrace(PTRACE_GETREGS, child, NULL, &reg);
                syscall = SYSCALL(&reg);

                if (syscall == SYS_open) {
                    if (sabo_hack_open_file(&reg, child) == SABO_FORBIDDEN) {
                        /* use forbidden dynamic shared file */
                        judge_flag = SABO_MC;
                        sabo_kill(child);
                        break;
                    }
                }

                if (sabo_syscall[syscall] == SABO_FORBIDDEN) {
                    judge_flag = SABO_MC;
                    sabo_kill(child);
                    break;
                }

                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                continue;
            }
        } else {
            if (in_spj_run) {
                /* not limit the spj.cc supporter need to confirm it */
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                continue;
            }
            /* Other case will be treated as MC */
            judge_flag = SABO_MC;
            sabo_kill(child);
            break;
        }
    }

    resinfo->judge_flag = judge_flag;
    if (!in_spj_run) {
        resinfo->time_used = time_used;
        resinfo->memory_used = memory_used;
    }
}


static void
sabo_set_limit(const sabo_run_config *config)
{
    /*time_limits */
    struct itimerval timer;
    gettimeofday(&timer.it_value, NULL);

    timer.it_interval.tv_usec = timer.it_interval.tv_sec = 0;
    timer.it_value.tv_sec = config->time_limits / 1000; /* seconds */
    timer.it_value.tv_usec = config->time_limits % 1000 * 1000; /* microseconds */

    setitimer (ITIMER_REAL, &timer, NULL);

    /* memory_limits KB */
    struct rlimit mem_limits; mem_limits.rlim_max = config->memory_limits * 1024;
    mem_limits.rlim_cur = config->memory_limits * 1024;
    setrlimit(RLIMIT_DATA, &mem_limits);
}


static void
sabo_child_run(const sabo_run_config *config, int spj_run)
{
    /* Note: Only the one using use_sandbox option
     * will execute that.*/

    /*Trace itself */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    freopen(config->in_path, "r", stdin);
    freopen(config->user_path, "w", stdout);
    freopen("/dev/null", "w", stderr);

    /*
     * set time limits and memory limits
     * but for spj src file, unnecessary
     * compare user.out with data.out
    */

    if (!spj_run) {
        sabo_set_limit(config);
    } else {
        // spj step
        execl(config->spj_path, "./sabo/spj", config->in_path, config->out_path, config->user_path, NULL);

        return;
    }

    /* exec the user process */
    if (config->use_sandbox) {
        execl(config->exe, "Main", NULL);
    } else {

        /*
         * Execute the java program with the jvm security policy
         * Stack size is 8 MB
         */
        execl(config->exe, "java", "-cp", "demo/", "-Xss8M", "-Djava.security.manager", "-Djava.security.policy==policy", "-Djava.awt.headless=TRUE", "Main", NULL);
    }
    /* TODO DB operate */
}


static void
sabo_work_spj(const sabo_run_config *config, sabo_result_info *res)
{
    /* For special judge
     * problem author need to support the spj.cc
     * and the spj file must be C or C++ now, i will add the java option in the
     * future, ^_^
     */

    pid_t child = fork();

    if (child < 0) {
        /* sabo_error_log(LOG_EMERG, "function: sabo_work_spj, fork error, client %s, thread exit", cliaddr); */
    }

    if (child == 0) {
        sabo_child_run(config, TRUE);
    } else {
        sabo_monitor_run(child, config, res, TRUE);
    }
}


static void
sabo_core_run(sabo_run_config *config, sabo_result_info *info)
{
    pid_t child;
    if ((child = fork()) < 0) {
        /* sabo_error_log(LOG_ALERT, "fork() failed: %s, client: %s, thread %d exit", strerror(errno), cliaddr, pthread_self()); */
    }

    if (child == 0) {
        sabo_child_run(config, FALSE);
    } else {
        sabo_monitor_run(child, config, info, FALSE);
    }
    if (config->is_spj) {
        sabo_work_spj(config, info);
    }
}


char*
process_arg(PyObject *arg) {
    PyObject *temp = PyUnicode_AsUTF8String(arg);
    return PyBytes_AsString(temp);
}


static PyObject*
py_run(PyObject *self, PyObject *args) {
    PyObject* judge_config;
    sabo_run_config config;
    PyArg_ParseTuple(args, "O", &judge_config);

    config.exe = process_arg(PyDict_GetItemString(judge_config, "exe"));
    config.code_path = process_arg(PyDict_GetItemString(judge_config, "code_path"));
    config.in_path = process_arg(PyDict_GetItemString(judge_config, "in_path"));
    config.out_path = process_arg(PyDict_GetItemString(judge_config, "out_path"));
    config.user_path = process_arg(PyDict_GetItemString(judge_config, "user_path"));
    config.spj_path = process_arg(PyDict_GetItemString(judge_config, "spj_path"));
    config.time_limits = atoi(process_arg(PyDict_GetItemString(judge_config, "time_limits")));
    config.memory_limits = atoi(process_arg(PyDict_GetItemString(judge_config, "memory_limits")));
    config.err_path = "/dev/null";
    config.is_spj = atoi(process_arg(PyDict_GetItemString(judge_config, "is_spj")));
    config.use_sandbox = atoi(process_arg(PyDict_GetItemString(judge_config, "use_sandbox")));

    sabo_result_info res;
    res.judge_flag = SABO_UNKNOWN;

    if (config.code_path == NULL || config.in_path == NULL ||
        config.out_path == NULL || config.user_path == NULL ||
        (config.is_spj && config.spj_path == NULL) ||
         (config.use_sandbox == 0 && config.exe == NULL)
         || config.time_limits == 0 || config.memory_limits == 0) {
        res.judge_flag = SABO_SYSERR;

        return Py_BuildValue("(iii)", res.judge_flag, 0, 0);
    }


    res.time_used = -1;
    res.memory_used = -1;
    sabo_core_init();
    sabo_core_run(&config, &res);

    if (res.judge_flag == SABO_TLE) {
        res.time_used = config.time_limits;
    } else if (res.judge_flag == SABO_MLE) {
        res.memory_used = config.memory_limits;
    }

    return Py_BuildValue("(iii)", res.judge_flag, res.time_used, res.memory_used);
}



static PyMethodDef coreMethods[] = {
    {"run", py_run, METH_VARARGS, "Sabo judger core"},
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef coreModule = {
    PyModuleDef_HEAD_INIT,
    "sabo_core",
    NULL,
    -1,
    coreMethods
};


// initial
PyMODINIT_FUNC
PyInit_sabo_core() {
    return PyModule_Create(&coreModule);
}
