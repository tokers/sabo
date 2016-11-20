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


import config
import time
import MySQLdb
from sabo_log import sabo_error_log


def sabo_db_connect(db_conf):
    ip      = db_conf["db_addr"]
    port    = db_conf["db_port"]
    user    = db_conf["db_user"]
    passwd  = db_conf["db_passwd"]
    db      = db_conf["db_name"]
    charset = "utf8"

    for i in range(db_conf["db_retry"]):
        try:
            mysql_db = MySQLdb.connect(host=ip, port=port, user=user, passwd=passwd, db=db, charset=charset)
        except Exception as e:
            sabo_error_log("error", "Connect to mysql failed: {0}".format(e))
        else:
            return mysql_db


# if there are some tasks didn't be judged,
# then the process will be blocked until the queue is empty.
def sabo_traversal_database(task_queue, db_conf):
    while True:
        # until all the tasks were processed.
        task_queue.join()

        db = sabo_db_connect(db_conf)
        if not db:
            time.sleep(db_conf["db_interval"])
            continue

        data_for_judge = sabo_get_data(db, db_conf)
        db_cursor = db.cursor()

        if data_for_judge is not None:
            for data in data_for_judge:
                try:
                    db_cursor.execute(config.get_pending_sql)
                    submit_id, problem_id, time_limits, memory_limits,lang, spj = db_cursor.fetchall()[0]

                    db_cursor.execute(config.get_solution_soucre_code.format(submit_id))
                    source, = db_cursor.fetchall()[0]

                    item_dict = {
                        'submit_id': submit_id,
                        'problem_id': problem_id,
                        'lang': lang,
                        'time_limits': int(time_limits), # MS
                        'memory_limits': int(memory_limits), # KB
                        'spj': spj,
                        'source': source,
                    }
                except Exception as e:
                    sabo_error_log("error", "fetch data from database failed: {0}".format(e))
                    db_cursor.close()
                    continue
                else:
                    sabo_error_log("info", "fetch data from database: submit_id: {0}, problem_id: {1}, lang: {2}, time_limits: {3}, memory_limits: {4}, spj: {5}".format(submit_id, problem_id, lang, time_limits, memory_limits, spj))

                    # put the data to the task queue(process safety).
                    task_queue.put(item_dict)
                    # update the submit status to Queuing
                    sabo_change_states(item_dict, config.judge_map["Queuing"], db_conf)
                    db_cursor.close()

        db.close()
        time.sleep(db_conf["db_interval"])


# Get the data which judge_status is Pending.
# Put the data to the task_queue which is process safety.
def sabo_get_data(db, db_conf):
    db_cursor = db.cursor()
    for i in range(db_conf["db_retry"]):
        try:
            db_cursor.execute(config.get_pending_sql)
            data = db_cursor.fetchall()
        except Exception as e:
            sabo_error_log("error", "get pending data from databse failed: {0}".format(e))
            continue
        else:
            db_cursor.close()
            return data


def sabo_change_states(item_dict, status_id, db_conf):
    db = sabo_db_connect(db_conf)
    if not db:
        return

    cursor = db.cursor()
    for i in range(db_conf["db_retry"]):
        try:
            cursor.execute(config.update_specific_submit_status_sql.format(status_id, item_dict['submit_id']))
            db.commit()

        except Exception as e:
            sabo_error_log("error", "update states failed: {0}".format(e))
            continue

        else:
            break

    cursor.close()
    db.close()


def sabo_write_ce_info(submit_id, ceinfo, db_conf):
    db = sabo_db_connect(db_conf)
    if not db:
        return

    cursor = db.cursor()
    for i in range(db_conf["db_retry"]):
        try:
            cursor.execute(conf.get_ceinfo.format(submit_id))
            find_all = db_cursor.fetchall()
            if find_all is None or len(find_all) == 0:
                cursor.execute(config.insert_ce_info_sql.format(submit_id,ce_info))
            else:
                cursor.execute(config.update_ceinfo.format(ce_info, submit_id))

        except Exception as e:
            sabo_error_log("error", "write ce info failed: {0}".format(e))
            continue
        else:
            break

    cursor.close()
    db.close()


def sabo_update_result(db_conf, res, timeused, memoryused, solution_id):
    db = sabo_db_connect(db_conf)
    if not db:
        return

    cursor = db.cursor()
    for i in range(db_conf["db_retry"]):
        try:
            cursor.execute(config.update_result_sql.format(res, timeused, memoryused, solution_id))
        except Exception as e:
            sabo_error_log("error", "update result for solution_id {0} failed: {1}".format(solution_id, e))
            continue
        else:
            break

    cursor.close()
    db.close()
