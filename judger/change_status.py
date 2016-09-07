'''
Change the submit status and write to the database.
'''
import config 
import MySQLdb
from datetime import datetime

def change_status(item_dict, db, status_id, log_lock, logging):
    '''
    update the status
    '''
    try:
        cursor = db.cursor()
        cursor.execute(config.update_specific_submit_status_sql.format(status_id, item_dict['submit_id']))
        db.commit()
        if log_lock.acquire():
            logging.info('{0} Change submit {1} status to {2}'.format(datetime.now(),item_dict['submit_id'],config.judge_status[status_id]))
            log_lock.release()
    except MySQLdb.OperationalError:
        if log_lock.acquire():
            logging.error('{0} database operation error.'.format(datetime.now()))
            log_lock.release()
    finally:
        cursor.close()
