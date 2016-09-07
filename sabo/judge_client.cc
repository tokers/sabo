/*
 * Noj Judger Core(Version Sabo)
 * Copyright (C) 2016  Alex(Zhang Chao)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "judge_client.h"

static void
sabo_init()
{
    memset(sabo_syscall, SABO_FORBIDDEN, sizeof(sabo_syscall));
    for (int i = 0; i < int(sizeof(sabo_syscall)/sizeof(int)); ++i) {
        sabo_syscall[sabo_syscall_whitelist[i]] = SABO_ALLOWED;
    }
}

/*
 * This function is used to check the file whether is allowed to open when the
 * child process called the open system call, if the file is not in the
 * file_white_list, user solution will be judged by MC(malicious code)
 *
 */

static bool
sabo_check_accessfile(const char * filepath, int flag)
{
    for (int i = 0; i < int(sizeof(sabo_sofile_whitelist) / sizeof(sabo_sofile)); ++i) {
        if (!strcmp(filepath, sabo_sofile_whitelist[i].first) && flag == sabo_sofile_whitelist[i].second) {
            return SABO_ALLOWED;
        }
    }
    return SABO_FORBIDDEN;
}

/* 
 * this function is used to get the filepath and flag, reference:
 * https://github.com/lodevil/Lo-runner
 * if long is 4 bytes, 4 char 
 * if long is 8 bytes, 8 char
 */

static bool
sabo_hack_open_file(struct user_regs_struct *reg, pid_t child)
{

    long file_temp[100];
    for (int i = 0; i < 100; ++i) {
        const char * test;
        long t = ptrace(PTRACE_PEEKDATA,child, REG_ARG_1(reg) + i * sizeof(long), NULL);

        file_temp[i] = t;
        test = (const char*)&file_temp[i];
        bool flag = false;
        for (int j = 0; j < (int)sizeof(long); ++j) {
            if (!test[j]) {
                file_temp[99] = 0;
                flag = true;
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
    unsigned int time_used = runinfo -> ru_utime.tv_sec * 1000+ runinfo -> ru_utime.tv_usec / 1000;
    time_used += runinfo -> ru_stime.tv_sec * 1000 + runinfo -> ru_stime.tv_usec / 1000;

    return time_used;
}

static unsigned int
get_process_runmem(const struct rusage *runinfo)
{

    /*
     * Get the used memory
     * ru_maxrss maybe the result is larger than the real usage
     * about ru_maxrss:
     * This is the maximum resident set size used (in kilobytes).
     * For RUSAGE_CHILDREN, this is the resident set size of the
     * largest child, not the maximum resident set
     * size of the process tree
     *
     * just one child, so it's ok
     */

    return runinfo->ru_maxrss;
}

static void
sabo_kill(pid_t child)
{
    /* kill the child process */
    kill(child, SIGKILL);
    
    wait(NULL); /* provent zombie process */

}

static void
sabo_monitor_run(pid_t child, sabo_result_info *res, bool in_spj_run, int memory_limits, bool use_sandbox) {

    int runstat;
    struct rusage runinfo;
    int judge_flag = SABO_UNKNOWN;
    int time_used, memory_used;

    time_used = -1;
    memory_used = -1;

    for (;;) {
        wait4(child, &runstat, 0, &runinfo);
        time_used = sabo_get_process_runtime(&runinfo);
        memory_used = sabo_get_process_runmem(&runinfo);

        if (!in_spj_run && memory_used > memory_limits) {
            judge_flag = SABO_MLE;
            sabo_kill(child);
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

                /* not limit the spj.cc supporter need to confirm it */
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

                    /*if like java with jvm sandbox, it's ok
                     * child run continue */
                    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                    continue;
                }
                long long syscall;
                struct user_regs_struct reg;

                // get the reg info
                ptrace(PTRACE_GETREGS, child, NULL, &reg);
                syscall = SYSCALL(&reg);

                if (syscall == SYS_open) {

                    if (!sabo_hack_open_file(&reg, child)) {

                        /* use forbidden dynamic shared file */
                        judge_flag = SABO_MC;
                        sabo_kill(child);
                        break;
                    }
                }

                if ((syscall < 0 || syscall > 2047) && sabo_syscall[syscall] == SABO_FORBIDDEN) {
                    /* Shit! use forbidden sys call */
                    judge_flag = SABO_MC;
                    sabo_kill(child);
                    break;
                }
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

        /* child run continue */
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }

     res->judge_flag = judge_flag;
     if (!in_spj_run) {
         res->time_used = time_used;
         res->memory_used = memory_used;
     }
}

static void
set_limit(const sabo_run_config *config)
{

    /*time_limits */
    struct itimerval timer;
    gettimeofday (&timer.it_value, NULL);

    timer.it_interval.tv_usec = timer.it_interval.tv_sec = 0;
    timer.it_value.tv_sec = config->time_limits / 1000; /* seconds */
    timer.it_value.tv_usec = config->time_limits % 1000 * 1000; /* microseconds */

    setitimer (ITIMER_REAL, &timer, NULL);

    /* memory_limits KB */
    struct rlimit mem_limits;
    mem_limits.rlim_max = config->memory_limits * 1024;
    mem_limits.rlim_cur = config->memory_limits * 1024;
    setrlimit(RLIMIT_DATA, &mem_limits);
}

static void
child_run(const sabo_run_config *config, bool in_spj_run)
{

    /* Note: Only the one using use_sandbox option 
     * will execute that.*/
    
    /*Trace itself */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    /* 
     * set time limits and memory limits 
     * but for spj src file, unnecessary
     * compare user.out with data.out
    */

    if (!in_spj_run) {
        set_limit(config);
    } else {
        // spj step
        int res = execl(config->spj_path, "./spj", config->in_path, config->out_path, config->user_path, NULL);
        if (res == -1) {
            return;
        }
        return;
    }

    /* exec the user process */
    freopen(config->in_path, "r", stdin);
    freopen(config->user_path, "w", stdout);
    freopen(config->err_path, "w", stderr);

    if (config->use_sandbox) {
        int res = execl(config->exe, "./Main", NULL);
        if (res == -1) {
            return;
        }

    } else {

        /* 
         * Execute the java program with the jvm security policy
         * Stack size is 8 MB
         */
        int res = execl(config->exe, "java", "-cp", config->code_path, "-Xss8M", "-Djava.security.manager", "-Djava.security.policy==policy", "-Djava.awt.headless=true", "Main", NULL);

        if (res == -1) {
            return;
        }
    }
    exit(0);
}


static void
work_common(const sabo_run_config *config, sabo_result_info * res)
{

    pid_t child = fork();
    
    if (child == 0) {
        /* child process */

        sabo_child_run(config);

    } else {
        /* judger process */
        sabo_monitor_run(child, res, false, config->memory_limits, config->use_sandbox);
    }
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

    if (child == 0) {
        child_run(config, true);
    } else {
        sabo_monitor_run(child, res, true); 
    } 
} 

static void
sabo_judger_run(const sabo_run_config *config, sabo_result_info *res)
{ 

    if (config == NULL || res == NULL) {
        return;
    }

    sabo_init();

    sabo_work_common(config, res);

    if (config -> is_spj && res -> judge_flag == SABO_AC) {
        sabo_work_spj(config, res);
    } 
}


char *
process_arg(PyObject *arg)
{
    PyObject *temp = PyUnicode_AsUTF8String(arg);
    return PyBytes_AsString(temp);
}

static
PyObject *py_run(PyObject *self, PyObject *args)
{

    error_reason = NULL;
    PyObject *judge_config;
    PyArg_ParseTuple(args, "O", &judge_config);

    char *exe = process_arg(PyDict_GetItemString(judge_config, "exe"));
    if (exe == NULL) {
        error_reason = "[Error raise]: You must tell core about the compiler path!";
    }

    char *code_path = process_arg(PyDict_GetItemString(judge_config, "code_path"));
    if (code_path == NULL) {
        error_reason = "[Error raise]: You must tell core about the code path!";
    }

    char *in_path = process_arg(PyDict_GetItemString(judge_config, "in_path"));
    if (in_path == NULL) {
        error_reason = "[Error raise]: You must tell core about the input data path!";
    }

    char *out_path = process_arg(PyDict_GetItemString(judge_config, "out_path"));
    if (out_path == NULL) {
        error_reason = "[Error raise]: You must tell core about the output data path!";
    }

    char *user_path = process_arg(PyDict_GetItemString(judge_config, "user_path"));
    if (user_path == NULL) {
        error_reason = "[Error raise]: You must tell core about the user's output data path!";
    }

    char *spj_path = process_arg(PyDict_GetItemString(judge_config, "spj_path"));

    if (user_path == NULL) {
        error_reason = "[Error raise]: You must tell core about the user's output data path!";
    }
    const char *err_path = "/dev/null";

    int time_limits, memory_limits;
    time_limits = atoi(process_arg(PyDict_GetItemString(judge_config, "time_limits")));
    memory_limits = atoi(process_arg(PyDict_GetItemString(judge_config, "memory_limits")));

    bool is_spj, use_sandbox;
    is_spj = atoi(process_arg(PyDict_GetItemString(judge_config, "is_spj")));
    use_sandbox = atoi(process_arg(PyDict_GetItemString(judge_config, "use_sandbox")));

    sabo_result_info res;
    sabo_run_config config = sabo_run_config(&exe, &code_path, &in_path, &out_path, &user_path, time_limits, memory_limits, is_spj, &spj_path, use_sandbox, &err_path);
    sabo_judger_run(&config, &res);
    return Py_BuildValue("(iii)", res.judge_flag, res.time_used, res.memory_used);
}

static PyMethodDef coreMethods[] = {
    {"run", py_run, METH_VARARGS, "the judge entry"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef coreModule = {
    PyModuleDef_HEAD_INIT,
    "core",
    NULL,
    -1,
    coreMethods
};

/* initial */
PyMODINIT_FUNC
PyInit_core()
{
    return PyModule_Create(&coreModule);
}
