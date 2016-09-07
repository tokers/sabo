'''
judge client
judge problem in the queue.
'''
from db_connect import db_connect
from multiprocessing import Lock
from shutil import move
import io
import shlex
import os
from os import getpid
import subprocess
import config
from datetime import datetime
from change_status import change_status
import core
import logging
from config import JAVA_PATH
from config import ROOT_DIR
from config import insert_ce_info_sql
from config import lang_tranfer
from config import code_lang
from config import log_info
from config import data_path
from config import judge_status

def compile(dirs, judge_client_id,submit_id, problem_id, lang, logging, log_lock, is_spj):
        '''
        compile the code with corresponding compiler or interprater
        '''
        utility = code_lang[lang_tranfer[int(lang)]]
        P = subprocess.Popen(utility, shell=True, cwd=dirs, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
        stdout, stderr = P.communicate()
        # exit code is zero, Compilation success.
        if P.returncode:
            with log_lock:
                logging.info(log_info.format(datetime.now(),getpid(),submit_id,problem_id,lang, 'Compilation Error'))
            ce_info = stderr.decode()
            ce_info = ce_info.replace('\'', '\\\'')
            ce_info = ce_info.replace('\"', '\\\"')
            return False,ce_info
        else:
            logging.info(log_info.format(datetime.now(),getpid(),submit_id,problem_id,lang,'Compilation Success'))
            if is_spj == '1':
                utility = "g++ spj.cc -o spj -Wall -O2 -std=c++0x"
                P = subprocess.Popen(utility, shell=True, cwd=dirs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = P.communicate ()
                #print(stdout.decode(), stderr.decode())
                if P.returncode:
                    print(P.returncode)
                    print(stderr.decode())
            return True,None

def run(submit_id, problem_id, code_path, time_limits, memory_limits, is_spj, lang): 
    in_path = os.path.join(data_path, str(problem_id), 'data.in') 
    out_path = os.path.join(data_path, str(problem_id), 'data.out')
    user_path = os.path.join(code_path, 'user.out')
    spj_path = os.path.join(code_path, 'spj')
    fin = open(in_path, 'r')
    fuser = open(user_path, 'w')
    if lang <= 1:
        exe = os.path.join(code_path, 'Main')
        use_sandbox = 1
        # C or C++ does not mind code_path
    #elif lang == 3:
    #	args = 'python2 {0}'.format(os.path.join(code_path, 'Main.py'))
    #	system_invoke[os.path.join(code_path,'Main.py')] = 0
    #	args = shlex.split(args)
    #	pyc = os.path.join(code_path, 'Main.pyc')
    #	system_invoke[pyc.format(submit_id)] = 0
    #elif lang == 4:
    #	system_invoke[os.path.join(code_path,'Main.py')] = 0
    #	args = 'python3.4 {0}'.format(os.path.join(code_path, 'Main.py'))
    #	args = shlex.split(args)
    #	pyc = os.path.join(code_path,'__pycache__/Main.cpython-34.pyc')
    #	system_invoke[pyc.format(submit_id)] = 0
    elif lang == 2:
        exe = JAVA_PATH
        use_sandbox = 0
    else:
        pass
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
    # running done.
    result = core.run(runcfg)
    fin.close()
    fuser.close()
    if result[0] != 0 or is_spj == '1':
        return result
    else:
        fuser = open(user_path, 'r')
        fout = open(out_path, 'r')
        try:
            user_out = fuser.read().rstrip().replace('\r', '')
            std_out = fout.read().rstrip().replace('\r', '')
        except:
            fuser.close()
            fout.close()
            return 4, result[1], result[2]
        else:
            fuser.close()
            fout.close()
        if std_out == user_out:
            res = 0
        else:
            std_out = std_out.replace(' ', '').replace('\n', '').replace('\t', '')
            user_out = user_out.replace(' ', '').replace('\n', '').replace('\t', '')
            if std_out == user_out:
                res = 1
            else:
                if std_out in user_out:
                    res = 6
                else:
                    res = 4
        return res,result[1],result[2] 


def judge(task, judge_client_id, db_lock, logging, log_lock):
        submit_id = task['submit_id']
        problem_id = task['problem_id']
        lang = task['lang']
        time_limits = task['time_limits']
        memory_limits = task['memory_limits']
        spj = task['spj']
        source = task['source']
        source_code_name = 'Main.';
        if lang == 0:
            source_code_name += 'cpp'
        elif lang == 1:
            source_code_name += 'c'
        elif lang == 2:
            source_code_name += 'java'
            time_limits *= 2
            memory_limits *= 2
        else:
            return
        dirs = os.path.join(ROOT_DIR, 'judgeclient{0}'.format(judge_client_id))
        if spj == '1':
            spj_path = os.path.join(data_path, str(problem_id), 'spj.cc') 
            if not os.path.isfile(spj_path):
                return
            spj_save_path = os.path.join(dirs, 'spj.cc')
            with io.open(spj_save_path, 'w+', encoding='utf8') as f:
                with open(spj_path, 'r') as f2:
                    f.write(f2.read())
        source_code_path = os.path.join(dirs, source_code_name)
        with io.open(source_code_path, 'w+', encoding='utf8') as f:
            f.write(source)
        with log_lock:
            logging.info(log_info.format(datetime.now(),getpid(),submit_id,problem_id,lang, 'Compiling'))
        db = db_connect(logging, log_lock)
        db_cursor = db.cursor()
        change_status(task, db, 13, log_lock, logging)
        file_result,ce_info = compile(dirs,judge_client_id, submit_id, problem_id, lang, logging, log_lock, spj)
        if file_result == False:
            db_cursor.execute("select solution_id from compileinfo where solution_id = {0}".format(submit_id))
            find_all = db_cursor.fetchall()
            if find_all is None or len(find_all) < 1:
                db_cursor.execute(insert_ce_info_sql.format(submit_id,ce_info))
            change_status(task, db, 7, log_lock, logging)
            db.close()
            res = 7
            # CE
        else:
            change_status(task, db, 14, log_lock, logging)
            res,timeused,memoryused = run(submit_id, problem_id, dirs, time_limits, memory_limits, spj, lang)
            db_cursor.execute("update solution set result={0},time={1},memory={2} where solution_id={3}".format(res,timeused,memoryused,submit_id))
            db.close()
            # start to run only if compile success.
            ## running done, write to db 
            #change_status.change_status(task,db_connect(),
        with log_lock:
            logging.info(log_info.format(datetime.now(),getpid(),submit_id,problem_id,lang, judge_status[res]))

def process_task_queue(task_queue, judge_client_id, db_lock, log_lock, logging):
        '''
        get the data from task queue, and process it(invoke the corresponding
        compilers or interpreters)
        '''
        while True:
                # wait if the task_queue now is empty.
                task = task_queue.get()
                judge(task, judge_client_id, db_lock, logging, log_lock) 
                task_queue.task_done()
