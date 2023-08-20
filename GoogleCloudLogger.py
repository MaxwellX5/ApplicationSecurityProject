import google.cloud.logging
from google.cloud.logging.handlers import CloudLoggingHandler
import logging
from initialize import *

# Initialize Cloud Logging client
CREDENTIALS = google.oauth2.service_account.Credentials.from_service_account_file("CloudLoggerKey.json")
CLIENT = google.cloud.logging.Client(credentials=CREDENTIALS)
HANDLER = CloudLoggingHandler(CLIENT)

# set formatter ONLY for google cloud logger
HANDLER.setFormatter(logging.Formatter('%(name)s - %(levelname)s: %(message)s'))

# initialize local logfile handler
LOGFILE_HANDLER = logging.FileHandler('logs/aspj.log')

# initialize console logging
CONSOLE_HANDLER = logging.StreamHandler()

# set formatter for local logfile and console logger
# this is because timestamps are included in google cloud logger explorer
LOGFILE_HANDLER.setFormatter(logging.Formatter('[%(asctime)s] %(name)s - %(levelname)s: %(message)s'))
CONSOLE_HANDLER.setFormatter(logging.Formatter('[%(asctime)s] %(name)s - %(levelname)s: %(message)s'))

# general logger for entire app
APP_LOGGER = logging.getLogger('App')
if cloudLoggerDisable == False:
    APP_LOGGER.addHandler(HANDLER)
APP_LOGGER.addHandler(LOGFILE_HANDLER)
APP_LOGGER.addHandler(CONSOLE_HANDLER)

LOGIN_LOGGER = logging.getLogger('Login')
LOGIN_LOGGER.setLevel(logging.INFO)
LOGIN_LOGGER.addHandler(HANDLER)
LOGIN_LOGGER.addHandler(LOGFILE_HANDLER)

ACCOUNT_LOGGER = logging.getLogger('Account')
ACCOUNT_LOGGER.setLevel(logging.INFO)
ACCOUNT_LOGGER.addHandler(HANDLER)
ACCOUNT_LOGGER.addHandler(LOGFILE_HANDLER)

ADMIN_LOGGER = logging.getLogger('Admin')
ADMIN_LOGGER.setLevel(logging.INFO)
ADMIN_LOGGER.addHandler(HANDLER)
ADMIN_LOGGER.addHandler(LOGFILE_HANDLER)

BILL_LOGGER = logging.getLogger('Bill')
BILL_LOGGER.setLevel(logging.INFO)
BILL_LOGGER.addHandler(HANDLER)
BILL_LOGGER.addHandler(LOGFILE_HANDLER)

DONATION_LOGGER = logging.getLogger('Donation')
if cloudLoggerDisable == False:
    DONATION_LOGGER.addHandler(HANDLER)
DONATION_LOGGER.addHandler(LOGFILE_HANDLER)
DONATION_LOGGER.addHandler(CONSOLE_HANDLER)

# loggers for app runtime
def app_log_debug(log_message):
    # only log debug messages if --verbose flag is passed in
    if verbose == True:
        APP_LOGGER.setLevel(logging.DEBUG)
        APP_LOGGER.debug(log_message)
        return
    else:
        return

def app_log_info(log_message):
    APP_LOGGER.setLevel(logging.INFO)
    APP_LOGGER.info(log_message)
    return

def app_log_warning(log_message):
    APP_LOGGER.setLevel(logging.WARNING)
    APP_LOGGER.warning(log_message)
    return

def app_log_critical(log_message):
    APP_LOGGER.setLevel(logging.CRITICAL)
    APP_LOGGER.critical(log_message)
    return

def login_info(description, user_agent, ip_address):
    log_message = f"Description: {description}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    LOGIN_LOGGER.setLevel(logging.INFO)
    LOGIN_LOGGER.info(log_message)
    return

def login_warning(description, user_agent, ip_address):
    log_message = f"Description: {description}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    LOGIN_LOGGER.setLevel(logging.WARNING)
    LOGIN_LOGGER.warning(log_message)
    return

def login_critical(description, user_agent, ip_address):
    log_message = f"Description: {description}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    LOGIN_LOGGER.setLevel(logging.CRITICAL)
    LOGIN_LOGGER.critical(log_message)
    return

def account_info(description, session_id, user_agent, ip_address):
    log_message = f"Description: {description}\nSession ID: {session_id}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    ACCOUNT_LOGGER.setLevel(logging.INFO)
    ACCOUNT_LOGGER.info(log_message)
    return

def account_warning(description, session_id, user_agent, ip_address):
    log_message = f"Description: {description}\nSession ID: {session_id}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    ACCOUNT_LOGGER.setLevel(logging.WARNING)
    ACCOUNT_LOGGER.warning(log_message)
    return

def account_critical(description, session_id, user_agent, ip_address):
    log_message = f"Description: {description}\nSession ID: {session_id}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    ACCOUNT_LOGGER.setLevel(logging.CRITICAL)
    ACCOUNT_LOGGER.critical(log_message)
    return

def admin_info(description, session_id, user_agent, ip_address):
    log_message = f"Description: {description}\nSession ID: {session_id}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    ADMIN_LOGGER.setLevel(logging.INFO)
    ADMIN_LOGGER.info(log_message)
    return

def admin_warning(description, session_id, user_agent, ip_address):
    log_message = f"Description: {description}\nSession ID: {session_id}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    ADMIN_LOGGER.setLevel(logging.WARNING)
    ADMIN_LOGGER.warning(log_message)
    return

def admin_critical(description, session_id, user_agent, ip_address):
    log_message = f"Description: {description}\nSession ID: {session_id}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    ADMIN_LOGGER.setLevel(logging.CRITICAL)
    ADMIN_LOGGER.critical(log_message)
    return

def bill_info(description, session_id, user_agent, ip_address):
    log_message = f"Description: {description}\nSession ID: {session_id}\nUser Agent: {user_agent}\nIP Address: {ip_address}"
    BILL_LOGGER.setLevel(logging.INFO)
    BILL_LOGGER.info(log_message)
    return 'itworked'

def bill_failed(description, session_id,error):
    log_message = f"Description: {description}\nSession ID: {session_id}\nError:{error}"
    BILL_LOGGER.setLevel(logging.WARNING)
    BILL_LOGGER.warning(log_message)
    return

def bill_critical(description, session_id):
    log_message = f'{description} with session_id of {session_id}'
    BILL_LOGGER.setLevel(logging.CRITICAL)
    BILL_LOGGER.critical(log_message)
    return


# loggers for donation section
def donation_log_debug(ip_address, session_id, log_message):
    # only log debug messages if --verbose flag is passed in
    if verbose == True:
        message = f"[{ip_address}, {session_id}] {log_message}"
        DONATION_LOGGER.setLevel(logging.DEBUG)
        DONATION_LOGGER.debug(message)
        return
    else:
        return

def donation_log_info(ip_address, session_id, log_message):
    message = f"[{ip_address}, {session_id}] {log_message}"
    DONATION_LOGGER.setLevel(logging.INFO)
    DONATION_LOGGER.info(message)
    return

def donation_log_warning(ip_address, session_id, log_message):
    message = f"[{ip_address}, {session_id}] {log_message}"
    DONATION_LOGGER.setLevel(logging.WARNING)
    DONATION_LOGGER.warning(message)
    return

def donation_log_critical(ip_address, session_id, log_message):
    message = f"[{ip_address}, {session_id}] {log_message}"
    DONATION_LOGGER.setLevel(logging.CRITICAL)
    DONATION_LOGGER.critical(message)
    return