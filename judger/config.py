from os import getcwd
from os import path
'''
This file is about the configuration of the judger,
such as database config, judge_status, code language.
Just for convience.  
'''

log_info = "{0} from judgeclient process:{1}, submit ID:{2}, problem ID:{3}, language:{4}judge result:{5}"
db_config = {
    'host': 'localhost',
    'user': 'root',
    'passwd': '',
    'db': 'jol',
    'charset': 'utf8'
}

# sql statements.
get_pending_sql = 'select solution_id,A.problem_id as problem_id,A.time_limit as time,A.memory_limit as memory,language, A.spj as spj from solution as B, problem as A where result in (11,12,13,14) and A.problem_id = B.problem_id'
update_specific_submit_status_sql = 'update solution set result={0} where solution_id={1}'
insert_ce_info_sql = "insert into compileinfo values({0},'{1}')"
check_problem_is_spj = "select spj from problem where problem_id={0}"
get_solution_soucre_code = "select source from source_code where solution_id={0}"

# the judge status
judge_status = [
    'Accepted', # 0
    'Presentation Error', # 1
    'Time Limit Exceeded', # 2
    'Memory Limit Exceeded', # 3
    'Wrong Answer', # 4
    'Runtime Error', # 5 
    'Output Limit Exceeded', # 6
    'Compilation Error', # 7
    'System Error', # 8
    'Malicious Code', # 9
    'Submit Failed', # 10
    'Pending', # 11
    'Queuing', #12
    'Compiling', # 13
    'Running', # 14
]

lang_tranfer = ['g++','gcc','java','python2','python3']
code_lang = { 
    'gcc': 'gcc Main.c -o Main -Wall -O2 -std=c99', 
    'g++': 'g++ Main.cpp -o  Main -Wall -O2 -std=c++0x',
    'java': 'javac Main.java',
    'python2': 'python2.7 -m py_compile Main.py',
    'python3': 'python3.4 -m py_compile Main.py',

    #extend ...
}

# problem data path
ROOT_DIR = path.dirname(getcwd())
data_path = '/home/alex/NOJ/data'
JAVA_PATH = '/usr/java/jdk/bin/java'
