#!/usr/bin/env python3
''' 
Put the data(from the database) to the task queue.  
''' 
import multiprocessing
from os import environ
from change_status import change_status 
import config 
from config import ROOT_DIR
import time
import logging
from db_connect import db_connect
from datetime import datetime
from judge_client import process_task_queue
import MySQLdb 
import sys
from os import cpu_count
from os import getpid 
from os import path
from os import makedirs
def get_submit_to_judge(db):
    ''' Get the data which judge_status is Pending.  Put the data to the task_queue which is process safety.  '''
    db_cursor = db.cursor()
    try:
        db_cursor.execute(config.get_pending_sql)  
        data = db_cursor.fetchall()
    except MySQLdb.OperationalError:
        logging.error("{0} Get pending submits error!".format(datetime.now()))
    else: 
    	return data 
    finally:
        db_cursor.close() 
        
def traversal_database(task_queue, db_lock, log_lock): 
    '''
    traversal the database every 5 seconds, if there are some tasks didn't be judged, then the process will be blocked until the queue is empty.
    '''
    while True:
        # until all the tasks were processed.
        task_queue.join()
        with db_lock:
            # connect to the database.
            db = db_connect(logging,log_lock)
            # use the Lock when connecting to the database
            data_for_judge = get_submit_to_judge(db)
            if data_for_judge is not None:
                for submit_id,problem_id,time_limits,memory_limits,lang, spj in data_for_judge:
                    db_cursor = db.cursor()
                    db_cursor.execute(config.get_solution_soucre_code.format(submit_id))  
                    source, = db_cursor.fetchall()[0]
                    item_dict = {
                            'submit_id': submit_id,
                            'problem_id': problem_id,
                            'lang': lang,
                            'time_limits': int(time_limits), # MS
                            'memory_limits': int(memory_limits), # KB
                            'spj': spj,
                            'source': source
                            }
                    # put the data to the task queue(process safety).
                    logging.info('GET pending submit, ID:{0}, problem ID:{1}, SPJ:{2}'.format(submit_id,problem_id,spj))
                    task_queue.put(item_dict)
                    # update the submit status to Queuing
                    change_status(item_dict, db, 12, log_lock,logging)
			# close the connection
                db.close() 
        # sleep 3 seconds.
        time.sleep(3)

if __name__ == '__main__':
    logging.basicConfig(
            filename = 'judged_status.log',
            level = logging.INFO
    )
    logging.info("{0}, Judge client start... Process ID is {1}".format(datetime.now(),getpid()))
    logging.info("Initial the task queue, the database lock...")
    task_queue = multiprocessing.JoinableQueue()
    db_lock = multiprocessing.Lock()
    log_lock = multiprocessing.Lock()
    logging.info("Make worker process...")
    logging.info("The platform contains {0} CPU core, start these worker process...".format(cpu_count()))
    
    for i in range(cpu_count()):
        logging.info("Initial work space for judge client {0}...".format(i))
        judge_client_work_path = path.join(ROOT_DIR,'judgeclient{0}'.format(i))
        if not path.exists(judge_client_work_path):
            makedirs(judge_client_work_path)
        worker = multiprocessing.Process(target=process_task_queue, args=(task_queue,i, db_lock,log_lock,logging))
        worker.start()
    traversal_database(task_queue, db_lock, log_lock)
