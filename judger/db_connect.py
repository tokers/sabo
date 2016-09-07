'''
This model just contains a python function which return a connection object if
connection is successful, else return None.
'''

from config import db_config
from datetime import datetime
import MySQLdb

def db_connect(logging,log_lock):
    '''
    Try to connect the database which configuration is in the config file.
    Be careful that the database server is started!
    '''
    while True:
        try:
            mysql_db = MySQLdb.connect(host=db_config['host'], user=db_config['user'], passwd=db_config['passwd'], db=db_config['db'], charset=db_config['charset'])
        except Exception:
            if log_lock.acquire():
                logging.ERROR('{0} judged connect database failed, retrying...'.format(datetime.now()))
                log_lock.release()
        else:
            return mysql_db
