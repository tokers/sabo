# -*- coding: utf-8 -*-

# ACMICPC problem online judger Sabo
# Copyright (C) 2016  zchao1995@gmail.com(Zhang Chao)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.  * * You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from shutil import move
from sabo_database import sabo_change_states
from sabo_database import sabo_update_result
from sabo_log import sabo_error_log

from config import code_lang
from config import judge_map
from config import spj_compile
from config import lang_tranfer
from config import judge_status

import io
import shlex
import subprocess
import sabo_core
import os


# compile the code with corresponding compiler
def compile(dirs, submit_id, problem_id, lang, is_spj):
        utility = code_lang[lang_tranfer[int(lang)]]
        P = subprocess.Popen(utility, shell=True, cwd=dirs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = P.communicate()

        # exit code is zero, Compilation success.
        if P.returncode:
            sabo_error_log("info", "Compilation Error for solution {0}, sabo worker: {1}".format(submit_id, os.getpid()))
            ce_info = stderr.decode()
            # prevent injecting
            ce_info = ce_info.replace('\'', '\\\'')
            ce_info = ce_info.replace('\"', '\\\"')
            return False, ce_info
        else:
            sabo_error_log("info", "Compilation Pass for solution {0}, sabo worker: {1}".format(submit_id, os.getpid()))
            if is_spj == '1':
                utility = spj_compile.format('spj.cc')
                P = subprocess.Popen(utility, shell=True, cwd=dirs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = P.communicate ()

                if P.returncode:
                    return False, None

            return True,None


def run(submit_id, problem_id, code_path, time_limits, memory_limits, is_spj,
        lang, conf):
    data_path = conf["base"]["data_path"]
    in_path = os.path.join(data_path, str(problem_id), 'data.in')
    out_path = os.path.join(data_path, str(problem_id), 'data.out')
    user_path = os.path.join(code_path, 'user.out')
    spj_path = os.path.join(code_path, 'spj')
    fin = open(in_path, 'r')
    fuser = open(user_path, 'w')
    if lang <= 1:
        exe = os.path.join(code_path, 'Main')
        use_sandbox = 1
    elif lang == 2:
        exe = conf["base"]["java_path"]
        use_sandbox = 0

    runcfg = {
        'exe': exe,
        'code_path': code_path,
        'in_path': in_path,
        'out_path': out_path,
        'user_path': user_path,
        'time_limits': str(time_limits),
        'memory_limits': str(memory_limits),
        'is_spj': str(is_spj),
        'spj_path': spj_path,
        'use_sandbox': str(use_sandbox)
    }

    result = sabo_core.run(runcfg)
    print(result[0], result[1], result[2])
    fin.close()
    fuser.close()

    if result[0] != judge_map["Accepted"] or is_spj:
        return result
    else:
        fuser = open(user_path, 'r')
        fout = open(out_path, 'r')
        user_out = fuser.read().rstrip().replace('\r', '')
        std_out = fout.read().rstrip().replace('\r', '')
        fuser.close()
        fout.close()
        if std_out == user_out:
            res = judge_map["Accepted"]
        else:
            std_out = std_out.replace(' ', '').replace('\n', '').replace('\t', '')
            user_out = user_out.replace(' ', '').replace('\n', '').replace('\t', '')
            if std_out == user_out:
                res = judge_map["Presentation Error"]
            else:
                if std_out in user_out:
                    res = judge_map["Output Limit Exceeded"]
                else:
                    res = judge_map["Wrong Answer"]

        return res, result[1], result[2]


def sabo_judge(conf, task, dirs):
    submit_id        = task['submit_id']
    problem_id       = task['problem_id']
    lang             = task['lang']
    time_limits      = task['time_limits']
    memory_limits    = task['memory_limits']
    spj              = task['spj']
    source           = task['source']
    source_code_name = 'Main.';
    data_path        = conf["base"]["data_path"]
    db_conf          = conf["db"]

    if lang == 0:
        source_code_name += 'cpp'
    elif lang == 1:
        source_code_name += 'c'
    elif lang == 2:
        source_code_name += 'java'
        time_limits *= conf["base"]["java_relax"]
        memory_limits *= conf["base"]["java_relax"]
    else:
        return

    if spj == '1':
        spj_path = None
        spj_save_path = "./spj.cc"

        for spj_file in ["spj.cc", "spj.c", "spj.cpp"]:
            spj_path = os.path.join(data_path, str(problem_id), spj_file)
            if os.path.isfile(spj_path):
                break
            spj_path = None
        if not spj_path:
            return

        with io.open(spj_save_path, 'w', encoding='utf8') as fw:
            with open(spj_path, 'r') as fr:
                fw.write(fr.read())

    source_code_save_path = os.path.join(dirs, source_code_name)
    with io.open(source_code_save_path, 'w', encoding='utf8') as f:
        f.write(source)

    sabo_change_states(task, judge_map["Compiling"], conf["db"])
    passed, ce_info = compile(dirs, submit_id, problem_id, lang, spj)

    if not passed and not ce_info:
        # SPJ compile failed, just return
        return

    # CE
    if passed == False:
        res = judge_map["Compilation Error"]
        sabo_write_ce_info(submit_id, ce_info, db_conf)
        sabo_change_states(task, res, conf["db"])
    else:
        sabo_change_states(task, judge_map["Running"], conf["db"])
        res, timeused, memoryused = run(submit_id, problem_id, dirs,
                time_limits, memory_limits, spj, lang, conf)

        sabo_update_result(db_conf, res, timeused, memoryused, submit_id)

        sabo_error_log("info", "solution_id: {0}, problem_id: {1}, lang: {2}, judged: {3}, timeused: {4}, memoryused: {5}" .format(submit_id, problem_id, lang, judge_status[res], timeused, memoryused))


def sabo_workers_do(conf, task_queue, result_queue):
    selfdir = os.path.join(conf["base"]["work_path"], "sabo." + str(os.getpid()))
    if not os.path.isdir(selfdir):
        os.mkdir(selfdir)
    os.chdir(selfdir)

    # block if no data
    while True:
        task = task_queue.get()
        sabo_judge(conf, task, selfdir)
        task_queue.task_done()
