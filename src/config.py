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


# sql statements.
get_pending_sql = 'select solution_id, A.problem_id as problem_id, A.time_limit as time, A.memory_limit as memory, language, A.spj as spj from solution as B, problem as A where result in (11, 12,13, 14) and A.problem_id = B.problem_id'

update_specific_submit_status_sql = 'update solution set result = {0} where solution_id = {1}'

insert_ce_info_sql = "insert into compileinfo values({0},'{1}')"

check_problem_is_spj = "select spj from problem where problem_id = {0}"

get_solution_soucre_code = "select source from source_code where solution_id = {0}"

get_ceinfo = "select solution_id from compileinfo where solution_id = {0}"

update_ceinfo = "update compileinfo set error = '{0}' where solution_id = {1}"

update_result_sql = "update solution set result = {0}, time = {1},memory = {2} where solution_id = {3}"

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
    'gcc': 'gcc Main.c -o Main -Wall -O3 -std=c99',
    'g++': 'g++ Main.cpp -o  Main -Wall -O3 -std=c++0x',
    'java': 'javac Main.java',
}

spj_compile = "g++ {0} -o spj -Wall -O3 -std=c++0x"

judge_map = {
    'Accepted': 0,
    'Presentation Error': 1,
    'Time Limit Exceeded': 2,
    'Memory Limit Exceeded': 3,
    'Wrong Answer': 4,
    'Runtime Error': 5,
    'Output Limit Exceeded': 6,
    'Compilation Error': 7,
    'System Error': 8,
    'Malicious Code': 9,
    'Submit Failed': 10,
    'Pending': 11,
    'Queuing': 12,
    'Compiling': 13,
    'Running': 14,
}
