/*
 * Noj Judger Core(Version Sabo)
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include "Python.h"

#if __WORDSIZE == 64
    #define SYSCALL(reg) ((reg)->orig_rax)
    #define REG_ARG_1(reg) ((reg)->rdi)
    #define REG_ARG_2(reg) ((reg)->rsi)
#else
    #define SYSCALL(reg) ((reg)->orig_eax)
    #define REG_ARG_1(reg) ((reg)->ebx)
    #define REG_ARG_2(reg) ((reg)->ecx)
#endif

const char * error_reason;
int sabo_errno;

/*
 * This micro are used to describe user program's running stat.
 * Note:
 *      RE is Runtime Error
 *      RE_DBZ is Runtime Error(DIVIDE BY ZERO)
 *      MC is malicious code(Are you kidding me? Want to crack this server? I
 *      will stop it!)
 */

#define SABO_ALLOWED true
#define SABO_FORBIDDEN false
#define SABO_UNKNOWN (-1)
#define SABO_INTERNAL_ERROR (-2) 
#define SABO_AC 0
#define SABO_WA 4
#define SABO_TLE 2
#define SABO_MLE 3
#define SABO_RE 5
#define SABO_RE_DBZ 9
#define SABO_MC 10

/* Use the hash table, check wheter the sys call is allowed in O(1) time */
bool sabo_syscall[1u << 11];

/* You can get the sys call table from https://filippo.io/linux-syscall-table */
int sabo_syscall_whitelist[] = {0,1,2,3,5,9,10,11,12,21,59,89,158,231};

/*
 * If you don't know which dynamic shared file needed
 * you can use the command strace, not only which dynamic 
 * shared file but also system call you can get.
 */

struct sabo_sofile {

    const char *first;
    int second;
    sabo_sofile(const char *temp, int mode) : first(temp), second(mode) {}
};

/* Hard code for shared object file */
sabo_sofile sabo_sofile_whitelist[] = {

    sabo_sofile("/etc/ld.so.cache", O_RDONLY),
    sabo_sofile("/usr/lib/x86_64-linux-gnu/libstdc++.so.6", O_RDONLY|O_CLOEXEC),
    sabo_sofile("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC),
    sabo_sofile("/lib/x86_64-linux-gnu/libm.so.6", O_RDONLY|O_CLOEXEC),
    sabo_sofile("/lib/x86_64-linux-gnu/libgcc_s.so.1", O_RDONLY|O_CLOEXEC),
    sabo_sofile("/lib64/libm.so.6", O_RDONLY),
    sabo_sofile("/lib64/libgcc_s.so.1", O_RDONLY),
    sabo_sofile("/lib64/libc.so.6", O_RDONLY),
    sabo_sofile("/usr/lib64/libstdc++.so.6", O_RDONLY),
};

struct sabo_result_info {

    int time_used;
    int memory_used;
    int judge_flag;
};
/*
 * var interpretation
 * exe the executable file path
 * code_path user src file path
 * in_path path of data.in
 * out_path path of data.out
 * user_path path of user.out(user program run result)
 * time_limits you know
 * memory_limits you know
 * is_spj judge type if true then this is a special judge 
 * spj_path is is meaningful if is_spj is true, the spj src code path, name is
 * spj.cc (only support C and C++)
 * 
 */

struct sabo_run_config {
    sabo_run_config();
    sabo_run_config(char **_exe, char **_code_path, char **_in_path, char **_out_path, char **_user_path, int _time_limits, int _memory_limits, bool _is_spj, char **_spj_path, bool _use_sandbox, const char **_err_path) : exe(*_exe), code_path(*_code_path), in_path(*_in_path), out_path(*_out_path), user_path(*_user_path), time_limits(_time_limits), memory_limits(_memory_limits), is_spj(_is_spj), spj_path(*_spj_path), use_sandbox(_use_sandbox), err_path(*_err_path) {}

    const char *exe;
    const char *code_path;
    const char *in_path;
    const char *out_path;
    const char *user_path;
    const int time_limits;
    const int memory_limits;
    const bool is_spj;
    const char *spj_path;
    const bool use_sandbox;
    const char *err_path;
};

static void sabo_error_record(const char * error_reason);

static void sabo_init();

/*
 * This function is used to check the file whether is allowed to open when the
 * child process called the open system call, if the file is not in the
 * file_white_list, user solution will be judged by MC(malicious code)
 *
 */
static bool sabo_check_accessfile(const char * filepath, int flag);


/* 
 * this function is used to get the filepath and flag, reference:
 * https://github.com/lodevil/Lo-runner
 * if long is 4 bytes, 4 char 
 * if long is 8 bytes, 8 char
 */
static bool sabo_hack_open_file(struct user_regs_struct *reg, pid_t child);

static unsigned int sabo_get_process_runtime(const struct rusage *runinfo);

static unsigned int sabo_get_process_runmem(const struct rusage *runinfo);


/* Monitor */
static void sabo_monitor_run(pid_t child, sabo_result_info *res, bool in_spj_run = false, int memory_limits = -1, bool use_sandbox = true);

static void sabo_set_limit(const sabo_run_config *config);

static void sabo_child_run(const sabo_run_config *config, bool in_spj_run = false);

static void sabo_work_common(const sabo_run_config *config, sabo_result_info *res);

static void sabo_work_spj(const sabo_run_config *config, sabo_result_info *res);

static void sabo_judger_run(const sabo_run_config *config, sabo_result_info *res);

static void sabo_kill(pid_t child);
