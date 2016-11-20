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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SABO_CORE_H
#define SABO_CORE_H

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <Python.h>


#if __WORDSIZE == 64
    #define SYSCALL(reg) ((reg)->orig_rax)
    #define REG_ARG_1(reg) ((reg)->rdi)
    #define REG_ARG_2(reg) ((reg)->rsi)
#else
    #define SYSCALL(reg) ((reg)->orig_eax)
    #define REG_ARG_1(reg) ((reg)->ebx)
    #define REG_ARG_2(reg) ((reg)->ecx)
#endif

#define   SABO_ALLOWED          1
#define   SABO_FORBIDDEN        0
#define   SABO_UNKNOWN          (-1)
#define   SABO_INTERNAL_ERROR   (-2)
#define   SABO_AC               0
#define   SABO_TLE              2
#define   SABO_MLE              3
#define   SABO_WA               4
#define   SABO_RE               5
#define   SABO_SYSERR           8
#define   SABO_RE_DBZ           5
#define   SABO_MC               10
#define   SABO_UNLIMIT          -1

#define   FALSE                   0
#define   TRUE                    1
#define   SABO_DEFTIME            1000
#define   SABO_DEFMEM             65536

#define   SABO_BUFFER_SIZE      1024

/*
 * var interpretation
 * exe the executable file path
 * code_path user src file path
 * in_path path of data.in
 * out_path path of data.out
 * user_path path of user.out(user program run result)
 * time_limits you know
 * memory_limits you know
 * is_spj judge type if TRUE then this is a special judge
 * spj_path is is meaningful if is_spj is TRUE, the spj src code path, name is
 * spj.cc (only support C and C++)
 *
 */
typedef struct {
    const char *exe;
    const char *code_path;
    const char *in_path;
    const char *out_path;
    const char *user_path;
    const char *spj_path;
    const char *err_path;
    int time_limits;
    int memory_limits;
    int is_spj;
    int use_sandbox;

} sabo_run_config;

typedef struct {
    int time_used;
    int memory_used;
    int judge_flag;
    int rid;
} sabo_result_info;

#endif
