#include <fcntl.h>
#include <Python.h>
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

#if __WORDSIZE == 64
    #define SYSCALL(reg) ((reg)->orig_rax)
    #define REG_ARG_1(reg) ((reg)->rdi)
    #define REG_ARG_2(reg) ((reg)->rsi)
#else
    #define SYSCALL(reg) ((reg)->orig_eax)
    #define REG_ARG_1(reg) ((reg)->ebx)
    #define REG_ARG_2(reg) ((reg)->ecx)
#endif

/*
 * This micro are used to describe user program's running stat.
 * Note:
 *      RE is Runtime Error
 *      RE_DBZ is Runtime Error(DIVIDE BY ZERO)
 *      MC is malicious code(Are you kidding me? Want to crack this server? I
 *      will stop it!)
 */

#define Allowed true
#define Forbidden false
#define UNKNOWN (-1)
#define AC 0
#define TLE 2
#define MLE 3
#define RE 5
#define RE_DBZ 9
#define MC 10

/*
 * Use the hash table, check wheter the sys call is allowed in O(1) time
 */
bool can_you_use_this_syscall[1u << 11];

/*
 * You can get the sys call table from https://filippo.io/linux-syscall-table/
 */
int allow_sys_call_white_list[] = {0,1,2,3,5,9,10,11,12,21,59,89,158,231};

/*
 *If you don't know which dynamic shared file needed
 * you can use the command strace, not only which dynamic 
 * shared file but also system call you can get.
 */

struct so_file {
    const char *first;
    int second;
    so_file(const char *temp, int mode) : first(temp), second(mode) {}
};

so_file allow_so_file_white_list[] = {
    so_file("/etc/ld.so.cache", O_RDONLY),
    so_file("/usr/lib/x86_64-linux-gnu/libstdc++.so.6", O_RDONLY|O_CLOEXEC),
    so_file("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC),
    so_file("/lib/x86_64-linux-gnu/libm.so.6", O_RDONLY|O_CLOEXEC),
    so_file("/lib/x86_64-linux-gnu/libgcc_s.so.1", O_RDONLY|O_CLOEXEC),
    so_file("/lib64/libm.so.6", O_RDONLY),
    so_file("/lib64/libgcc_s.so.1", O_RDONLY),
    so_file("/lib64/libc.so.6", O_RDONLY),
    so_file("/usr/lib64/libstdc++.so.6", O_RDONLY),
};

struct result_info {
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

struct run_config {
    run_config();
    run_config(char **_exe, char **_code_path, char **_in_path, char **_out_path, char **_user_path, int _time_limits, int _memory_limits, bool _is_spj, char **_spj_path, bool _use_sandbox, const char **_err_path) : exe(*_exe), code_path(*_code_path), in_path(*_in_path), out_path(*_out_path), user_path(*_user_path), time_limits(_time_limits), memory_limits(_memory_limits), is_spj(_is_spj), spj_path(*_spj_path), use_sandbox(_use_sandbox), err_path(*_err_path) {}

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


void _init();

/*
 * This function is used to check the file whether is allowed to open when the
 * child process called the open system call, if the file is not in the
 * file_white_list, user solution will be judged by MC(malicious code)
 *
 */
bool check_the_access_file(const char * filepath, int flag);


/* 
 * this function is used to get the filepath and flag, reference:
 * https://github.com/lodevil/Lo-runner
 * if long is 4 bytes, 4 char 
 * if long is 8 bytes, 8 char
 */
bool hack_open_file(struct user_regs_struct *reg, pid_t child);

unsigned int get_process_runtime(const struct rusage *runinfo);

unsigned int get_process_runmem(const struct rusage *runinfo);


// Monitor
void father_run(pid_t child, result_info *res, bool in_spj_run = false, int memory_limits = -1, bool use_sandbox = true);


void set_limit(const run_config *config);

void child_run(const run_config *config, bool in_spj_run = false);
void work_common(const run_config *config, result_info *res);
void work_spj(const run_config *config,result_info *res);
void judger_run(const run_config *config, result_info *res);
