import base64
import hashlib
import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import io
import os
import re
import time
import secrets,string
import uuid
from datetime import datetime, timedelta
from functools import wraps
from referral_code import encrypt_referral_code, decrypt_referral_code
import matplotlib.pyplot as plt
import phonenumbers
import requests
import stripe
from better_profanity import profanity
from dotenv import load_dotenv
from firebase_admin import auth, firestore
from firebase_admin.auth import UserRecord
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, generate_csrf
from itsdangerous import SignatureExpired, URLSafeTimedSerializer
from werkzeug.datastructures import MultiDict
from werkzeug.utils import secure_filename

import Billscanning
import VirusTotalPDF
from sexyencryption import decrypt, encrypt
from DBRetrieve import *
from DonationValidation import *
from firebaseconfig import (auth, db_ref, donation_bucket,
                            donation_cloud_storage, donation_db, pyreauth)
from Forms import (ChangePasswordForm, CreateMissionForm, CreateProductForm,
                   CreateStaffForm, CreateUserForm, DeleteAccountForm,
                   DonationForm, LoginForm, MissionEvidenceForm, ProfileForm,
                   ResetPassForm, TwoFactorForm, ResetPasswordForm, CreateRejectionForm)
from GoogleAuthenticator2FA import (generate_qr, generate_qrurl,
                                    generate_secret, otpverify)
from GoogleCloudLogger import *
from initialize import *
from inputfiltering import filter_input
from sessions import expiry_check, generate_session_id
from virustotalconfig import analyse_pfp
import threading
from flask_mail import Mail, Message
import mimetypes
from FaceID import capture_face, verify_face, register_face, detect_face
import html
app_log_info("App started")
app_log_debug(f"[System: {info.system}, Node: {info.node}, Release: {info.version}, Version: {info.version}]")
app_log_debug(f"Started with arguments: {args}")
load_dotenv()
# initialize flask app
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
#Initialize mail
app.config['MAIL_SERVER'] = "smtp-mail.outlook.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv("MAIL_EMAIL")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = True
mail = Mail(app)
s = URLSafeTimedSerializer(os.getenv("SERAILZER_KEY"))

#auto delete referral
scheduler = BackgroundScheduler()
scheduler.start()
def delete_expired_referral_codes():
    now = datetime.now()
    expired_referrals = donation_db.collection('referral_code').where('expiryDate', '<=', now).get()
    for referral in expired_referrals:
        referral.reference.delete()


#For threading
userlocks = {}
user_running_flags = {}
referlock = {}
refer_running_flags = {}
donation_admin_lock = {}
donation_admin_running_flags = {}


# initialize stripe
stripe.api_key = os.getenv("STRIPE_API_KEY")
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per second"])

csp = {
    'script-src': [
        "'self'",
        "https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js",
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js',
        'https://www.google.com/recaptcha/',
        'https://www.virustotal.com',
        'https://www.googleapis.com',
        'https://use.fontawesome.com',
        'https://www.google.com/recaptcha/api.js',
        'https://firebasestorage.googleapis.com/',

    ],
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css',
        'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css',
        'https://use.fontawesome.com/releases/v5.14.0/css/all.css',
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css',
        'https://maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css',
        'https://use.fontawesome.com/releases/v5.14.0/css/all.css',
        'data:'
    ],
    'img-src': [
        "'self'",
        'https://use.fontawesome.com',
        'https://firebasestorage.googleapis.com/',
        'https://www.w3.org/',
        'data:',
        'blob:'
    ],
    'font-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://use.fontawesome.com',
        'https://use.fontawesome.com/releases/v5.14.0/css/all.css'
    ],
    'frame-src': [
        "'self'",
        'https://www.google.com/recaptcha/',
        'https://www.google.com/recaptcha/api.js'
    ]
}

app.config['TALISMAN_FORCE_HTTPS'] = False

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    force_https=False,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite=None,
    x_xss_protection=True,
)

def get_ip_address():
    try:
        ip = request.headers.get('X-Forwarded-For', get_remote_address())
        return ip
    except:
        return 'Unknown'

@app.context_processor
def inject_user_utils():
    return {'get_user_attribute_unencrypted': get_user_attribute_unencrypted}


def check_expiry(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        session_id = session.get('session_id')
        if expiry_check(session_id) == True:
            flash("Session expired")
            return redirect(url_for('logout'))
        return func(*args, **kwargs)

    return decorated_function


def verify_session(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        session_id = session.get('id')
        if session_id == None:
            flash("Please login to access this page")
            return redirect(url_for('login'))
        sessions_ref = db_ref.child("sessions")
        query_result = sessions_ref.order_by_child('session_id').equal_to(session_id).get()
        for user_id, user_data in query_result.items():
            if user_data['session_id'] == session_id and expiry_check(session_id) == False:
                print("Valid session")
                break
            elif user_data['session_id'] == session_id and expiry_check(session_id) == True:
                print("Session expired")
                flash("Session expired")
                return redirect(url_for('logout'))
        if len(query_result) == 0:
            flash("Another device has logged into your account. Please login again to continue.")
            return redirect(url_for('logout'))

        return func(*args, **kwargs)

    return decorated_function


def refresh_session(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        time = datetime.now()
        if isinstance(time, datetime):
            time = time.isoformat()
        sessions_ref = db_ref.child("sessions")
        query_result = sessions_ref.order_by_child('session_id').equal_to(session.get('id')).get()
        for user_id, user_data in query_result.items():
            if user_data['session_id'] == session.get('id'):
                sessions_ref.child(user_id).update({"last_active": time})
        return func(*args, **kwargs)

    return decorated_function


def redirect_logged_in(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'id' in session:
            return redirect(url_for('home'))
        return func(*args, **kwargs)

    return decorated_function


def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        """
        Logged in check here
        """
        if 'id' in session:
            return func(*args, **kwargs)
        flash("You must be logged in to access this page.")
        return redirect(url_for('login'))

    return decorated_function


def roles_required(roles: list[str]):
    """
    E.g:
    @app.route('/leaderboardadmin')
    @roles_required(["Admin", "Leaderboard Manager"])
    """

    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            """Role Check Here"""
            user_id = session.get("id")
            if not user_id:
                flash("You must be logged in to access this page.")
                return redirect(url_for("login"))

            user_role = get_user_attribute_unencrypted(user_id, "role")

            if not user_role or user_role not in roles:
                return redirect(url_for("home"))

            return func(*args, **kwargs)

        return decorated_function

    return decorator


def check_lockout(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        """Lockout Check Here"""
        user_id = get_user_attribute_unencrypted(session.get("id"), 'id')
        if user_id:
            user = auth.get_user(user_id)
            if user.disabled:
                session.clear()
                flash("Your account has been locked for violating our Terms of Service.")
                return redirect(url_for("login"))

        return func(*args, **kwargs)

    return decorated_function




@app.route('/')
@limiter.limit("10/second", override_defaults=False)
def home():
    donation_form = DonationForm(request.form)
    if 'id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html', donation_form=donation_form)


@app.route('/dashboard', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def dashboard():
    donation_form = DonationForm(request.form)
    client_ip = get_ip_address()
    print("IP: ",client_ip)
    return render_template('dashboard.html', donation_form=donation_form)


@app.route('/logout', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
def logout():
    if 'id' not in session:
        return redirect(url_for('home'))
    sessions_ref = db_ref.child("sessions")
    query_result = sessions_ref.order_by_child('session_id').equal_to(session['id']).get()
    for session_id, session_data in query_result.items():
        if session_data.get('session_id') == session['id']:
            sessions_ref.child(session_id).delete()
    account_info("User logged out", session['id'], request.headers.get('User-Agent'), get_ip_address())
    session.clear()
    print("Session over")
    return redirect(url_for('home'))


@app.route('/donation-form', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
def donation_form():
    donation_form = DonationForm(request.form)
    if request.method == 'POST':

        donation_log_debug(get_ip_address(), session['id'], "Created new donation form")

        # validate form
        if donation_form_validate(request.form) == False:
            return redirect(request.url)

        # get form data from html
        session['donation_amount'] = float(request.form['amount'])
        session['donation_points'] = float(
            request.form['amount']) * 69  # a highly complex algorithm to calculate points
        session['donation_comment'] = request.form['comment']
        session['donation_anonymous'] = 'anonymous' in request.form
        session['donation_id'] = str(uuid.uuid4())

        donation_log_debug(get_ip_address(), session['id'], f"donation-form[{request.form}]")
        donation_log_debug(get_ip_address(), session['id'], f"donation-details[donation_amount={session['donation_amount']}, donation_points={session['donation_points']}, donation_comment={session['donation_comment']}, donation_anonymous={session['donation_anonymous']}]")

        return redirect(url_for('create_checkout_session'))
    return render_template('donation-form.html', donation_form=donation_form)


# entire stripe checkout session
@app.route('/create-checkout-session', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
def create_checkout_session():
    # retrieve donation amount and convert to cents
    donation_amount = int(session['donation_amount'] * 100)
    # da checkout session
    donation_log_info(get_ip_address(), session['id'], "Creating donation checkout session...")
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card', 'grabpay', 'paynow'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'sgd',
                        'product_data': {
                            'name': 'Donation',
                        },
                        # crucial to specify how much to donate
                        'unit_amount': donation_amount,
                    },
                    'quantity': 1,
                }
            ],
            mode='payment',
            success_url=hostURL + '/donation-success-process',
            cancel_url=hostURL + '/donation-cancel',
            automatic_tax={'enabled': False},
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)


@app.route('/donation-success-process')
@limiter.limit("10/second", override_defaults=False)
def donation_success_process():

    # firstly check if donation transaction record already exist as user can come back to this approute and spam the records
    # retrieve things from donation collection to display in table below
    donation_log_debug(get_ip_address(), session['id'], "Retrieving from donation collection database...")

    donation_db_list = []

    donation_db_docs = donation_db.collection('donation').stream()
    for donation_db_doc in donation_db_docs:
        # convert to dict
        donation_db_doc = donation_db_doc.to_dict()

        # get profile pic
        donation_db_doc['image_url'] = cloud_storage_get_profile_image_url(donation_db_doc['user_id'])

        # put into list
        donation_db_list.append(donation_db_doc)

    # default sort by date
    donation_db_list.sort(key=lambda x: x['timestamp'], reverse=True)
    donation_db_list_donated = sorted(donation_db_list, key=lambda x: x['points'], reverse=True)

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    # iterate through list of donation documents
    for donation_db_doc in donation_db_list:
        if donation_db_doc['donation_id'] == session['donation_id']:
            # if found just make user go to success page instead of uploading the same document
            donation_log_warning(get_ip_address(), session['id'], "User reloaded /donation-success-process multiple times to cheat the system")
            return redirect(url_for("donation_success"))
    donation_log_info(get_ip_address(), session['id'], "New donation transaction detected, adding new donation document to database...")

    donation_details = {}

    donation_details['anonymous'] = session['donation_anonymous']

    # if session['id'] does not exist then will return error
    try:
        session['donation_user_id'] = get_user_attribute_unencrypted(session['id'], 'id')
        donation_login = True
    # if error that means not logged in
    except KeyError:
        donation_login = False

    # logout and anon
    if donation_details['anonymous'] == True or donation_login == False:
        session['donation_username'] = "Anonymous"
        donation_details['anonymous'] = True
    # login and anon
    elif donation_details['anonymous'] == True and donation_login == True:
        session['donation_username'] = "Anonymous"
        donation_details['anonymous'] = True
    # logout and anon
    elif donation_details['anonymous'] == False and donation_login == False:
        session['donation_username'] = "Anonymous"
        donation_details['anonymous'] = True
    # login and non anon
    elif donation_details['anonymous'] == False and donation_login == True:
        session['donation_username'] = get_user_attribute_encrypted(session['id'], 'username')
        donation_details['anonymous'] = False

    # user is logged in and non anon, push to both user and donation collection
    if donation_details['anonymous'] == False:
        donation_db_ref = donation_db.collection('users').document(get_user_attribute_unencrypted(session['id'], 'id'))
        donation_db_doc = donation_db_ref.get().to_dict()

        # if user old, points attribute will exist, retrieve from dict
        try:
            old_donation_points = (donation_db_doc['points'])
        # if user new, points attribute will not exist, use 0 for now, below function will add attribute
        except:
            old_donation_points = 0

        new_donation_points = old_donation_points + session['donation_points']

        # upload to firestore FOR USERS
        donation_db_ref = donation_db.collection('users').document(get_user_attribute_unencrypted(session['id'], 'id'))
        donation_db_ref.set({
            'user_id': get_user_attribute_unencrypted(session['id'], 'id'),
            'username': session['donation_username'],
            'points': new_donation_points,
        })
        donation_log_debug(get_ip_address(), session['id'], "Pushed updated user data to users collection")

        # also upload to firestore FOR DONATION
        # first generate a random id for each donation
        donation_id = session['donation_id']
        donation_db_ref = donation_db.collection('donation').document(donation_id)
        donation_db_ref.set({
            'donation_id': donation_id,
            'user_id': session['donation_user_id'],
            'username': session['donation_username'],
            'amount': session['donation_amount'],
            'points': session['donation_points'],
            'comment': session['donation_comment'],
            'timestamp': datetime.now().isoformat(),
            'timestamp_formatted': datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        })
        donation_log_debug(get_ip_address(), session['id'], "Pushed donation details to donation collection")

    # user is not logged in or is anon, do not push to user collection
    else:
        donation_log_debug(get_ip_address(), session['id'], "User is not logged in or anonymous")
        donation_log_debug(get_ip_address(), session['id'], "Skipped pushing to user collection")
        session['donation_username'] = 'Anonymous'
        # also upload to firestore FOR DONATION
        donation_id = str(uuid.uuid4())
        donation_db_ref = donation_db.collection('donation').document(donation_id)
        donation_db_ref.set({
            'donation_id': donation_id,
            'user_id': 'Anonymous',
            'username': 'Anonymous',
            'amount': session['donation_amount'],
            'points': session['donation_points'],
            'comment': session['donation_comment'],
            'timestamp': datetime.now().isoformat(),
            'timestamp_formatted': datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        })
        donation_log_debug(get_ip_address(), session['id'], "Pushed donation details to donation collection")

    donation_log_info(get_ip_address(), session['id'], "Donation successful")
    donation_log_info(get_ip_address(), session['id'], f"Donation success [donation_username={session['donation_username']}, donation_points={session['donation_points']}, donation_comment={session['donation_comment']}]")

    return redirect('/donation-success')


@app.route('/donation-success')
@limiter.limit("10/second", override_defaults=False)
def donation_success():
    return render_template('donation-success.html', donation_username=session['donation_username'],
                           donation_points=session['donation_points'], donation_comment=session['donation_comment'])


@app.route('/donation-cancel')
@limiter.limit("10/second", override_defaults=False)
def donation_cancel():
    donation_log_info(get_ip_address(), session['id'], "Donation cancelled")
    return render_template('donation-cancel.html')


@app.route('/donation-leaderboard')
@limiter.limit("10/second", override_defaults=False)
def donation_leaderboard():
    donation_db_list = []


    # declare temp dictionary for user's details
    donation_details = {}
    donation_details['points'] = 69
    donation_details['level'] = 69
    donation_details['progress'] = 69
    donation_details['user_id'] = 'None'
    
    # see if guy is logged in
    try:
        donation_details['user_id'] = get_user_attribute_unencrypted(session['id'], 'id')
        donation_details['login'] = True
    except:
        donation_details['login'] = False

    # see if guy is initial user without donations
    try:
        donation_log_debug(get_ip_address(), session['id'], f"Retrieving donation progress of user {donation_details['user_id']}...")

        # if guy is NOT initial user with donations
        donation_db_ref = donation_db.collection('users').document(donation_details['user_id'])
        donation_db_doc = donation_db_ref.get().to_dict()
        donation_details['points'] = donation_db_doc['points']

        # do some highly complex and tedious calculations wawaweewa
        donation_details['level'] = donation_details['points'] // 100
        donation_details['progress'] = round(donation_details['points'] - (donation_details['level'] * 100), 2)
        donation_log_debug(get_ip_address(), session['id'], f"Donation progress {donation_details}")
    except:
        # if guy is initial user
        # technically dont need this cos everything declared at the front alr
        donation_details['points'] = 0
        donation_details['level'] = 0
        donation_details['progress'] = 0
        donation_log_debug(get_ip_address(), session['id'], f"New user detected, donation progress {donation_details}")

    # for leaderboard    
    # get all documents from donation collection
    
    donation_log_debug(get_ip_address(), session['id'], "Retrieving from donation collection database...")
    
    donation_db_docs = donation_db.collection('donation').stream()
    for donation_db_doc in donation_db_docs:
        # convert to dict
        donation_db_doc = donation_db_doc.to_dict()

        # get profile pic
        donation_db_doc['image_url'] = cloud_storage_get_profile_image_url(donation_db_doc['user_id'])

        # put into list
        donation_db_list.append(donation_db_doc)

    # default sort by date
    donation_db_list.sort(key=lambda x: x['timestamp'], reverse=True)
    donation_db_list_donated = sorted(donation_db_list, key=lambda x: x['points'], reverse=True)

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    # for rewards
    # retrieve things from database to display in table below

    donation_log_debug(get_ip_address(), session['id'], "Retrieving from rewards collection database...")

    donation_db_rewards_list = []
    donation_db_rewards_docs = donation_db.collection('rewards').stream()
    for donation_db_rewards_doc in donation_db_rewards_docs:
        # convert to dict
        donation_db_rewards_doc = donation_db_rewards_doc.to_dict()

        # convert levels into int
        donation_db_rewards_doc['level'] = int(donation_db_rewards_doc['level'])

        # see if the level thing is within the range of the thing
        if 0 <= donation_db_rewards_doc['level'] <= donation_details['level']:
            # only append the rewards the user achieved to the list
            donation_db_rewards_list.append(donation_db_rewards_doc)

    # sort list of dicts by level ascending
    donation_db_rewards_list.sort(key=lambda x: x['level'], reverse=False)

    donation_log_debug(get_ip_address(), session['id'], "Retrive success")

    # retrieve things from users collection to display in table below

    donation_log_debug(get_ip_address(), session['id'], "Retrieving from users collection database...")

    donation_db_users_list = []
    donation_db_users_docs = donation_db.collection('users').stream()
    for donation_db_users_doc in donation_db_users_docs:
        # convert to dict
        donation_db_users_doc = donation_db_users_doc.to_dict()

        # calculate amount donated from points
        donation_db_users_doc['amount'] = round(float(donation_db_users_doc['points']) / 69, 2)

        # get profile pic
        donation_db_users_doc['image_url'] = cloud_storage_get_profile_image_url(donation_db_users_doc['user_id'])

        # put new things into list
        donation_db_users_list.append(donation_db_users_doc)

    donation_db_users_list.sort(key=lambda x: x['points'], reverse=True)

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    return render_template('donation-leaderboard.html', donation_db_list=donation_db_list,
                           donation_db_users_list=donation_db_users_list, donation_details=donation_details,
                           donation_db_rewards_list=donation_db_rewards_list)


@app.route('/donation-admin', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin():
    # retrieve things from donation collection to display in table below
    donation_log_debug(get_ip_address(), session['id'], "Retrieving from donation collection database...")

    donation_db_list = []
    donation_db_docs = donation_db.collection('donation').stream()
    for donation_db_doc in donation_db_docs:
        # convert to dict
        donation_db_doc = donation_db_doc.to_dict()

        # put new things into list
        donation_db_list.append(donation_db_doc)

    donation_db_list.sort(key=lambda x: x['timestamp'], reverse=True)

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    # retrieve things from users collection to display in table below

    donation_log_debug(get_ip_address(), session['id'], "Retrieving from users collection database...")

    donation_db_users_list = []
    donation_db_users_docs = donation_db.collection('users').stream()
    for donation_db_users_doc in donation_db_users_docs:
        # convert to dict
        donation_db_users_doc = donation_db_users_doc.to_dict()

        # get profile pic
        donation_db_users_doc['image_url'] = cloud_storage_get_profile_image_url(donation_db_users_doc['user_id'])

        # put new things into list
        donation_db_users_list.append(donation_db_users_doc)

    donation_db_users_list.sort(key=lambda x: x['points'], reverse=True)

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    # retrieve things from rewards collection to display in table below

    donation_log_debug(get_ip_address(), session['id'], "Retrieving from rewards collection database...")

    donation_db_rewards_list = []
    donation_db_rewards_docs = donation_db.collection('rewards').stream()
    for donation_db_rewards_doc in donation_db_rewards_docs:
        # convert to dict
        donation_db_rewards_doc = donation_db_rewards_doc.to_dict()

        # convert levels into int
        donation_db_rewards_doc['level'] = int(donation_db_rewards_doc['level'])

        # put new things into list
        donation_db_rewards_list.append(donation_db_rewards_doc)

    # sort list of dicts by level ascending
    donation_db_rewards_list.sort(key=lambda x: x['level'], reverse=False)

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    # retrieve things from profanities collection to display in table below

    donation_log_debug(get_ip_address(), session['id'], "Retrieving from profanities collection database...")

    donation_db_profanities_list = []
    # declare a dictionary for donation profanities statistics
    donation_profanities_statistics = {}
    donation_profanities_statistics['total_count'] = 0
    donation_profanities_statistics['applied_count'] = 0
    donation_db_profanities_docs = donation_db.collection('profanities').stream()
    for donation_db_profanities_doc in donation_db_profanities_docs:
        # convert to dict
        donation_db_profanities_doc = donation_db_profanities_doc.to_dict()

        # put new things into list
        donation_db_profanities_list.append(donation_db_profanities_doc)

        # increment 1 to total count
        donation_profanities_statistics['total_count'] += 1

        # check for true value
        if donation_db_profanities_doc['enabled'] == True:
            donation_profanities_statistics['applied_count'] += 1

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    # start of form section
    donation_form = DonationForm(request.form)

    if request.method == 'POST':

        userid = session['id']

        # check if a process is already running for this user
        if donation_admin_running_flags.get(userid, False):
            session['Error'] = 'Threading'
            flash('Another reward is currently being created/updated, please try again in 30 seconds', 'warning')
            return redirect(request.url)

        if userid not in donation_admin_lock:
            donation_admin_lock[userid] = threading.Lock()

        with donation_admin_lock[userid]:
            # inside this lock set the flag showing something is happening for this user
            donation_admin_running_flags[userid] = True

            try:
                donation_log_debug(get_ip_address(), session['id'], "Created new donation-admin form")

                # get form data from html
                level = request.form['level']
                name = request.form['name']
                description = request.form['description']
                image = request.files['img_file']

                donation_log_debug(get_ip_address(), session['id'], f"Donation admin form [{request.form}]")

                # validate form
                if donation_form_validate_rewards == False:
                    return redirect(request.url)

                # check for issues in image uploaded
                if donation_file_check(image) == False:
                    return redirect(request.url)

                # check if file uploaded is image filetype
                if donation_image_check(image) == False:
                    return redirect(request.url)

                # re-fetch the rewards list from database after getting lock
                donation_log_debug(get_ip_address(), session['id'], "Retrieving from donation collection database...")

                donation_db_rewards_list = []
                donation_db_rewards_docs = donation_db.collection('rewards').stream()
                for donation_db_rewards_doc in donation_db_rewards_docs:
                    # convert to dict
                    donation_db_rewards_doc = donation_db_rewards_doc.to_dict()

                    # convert levels into int
                    donation_db_rewards_doc['level'] = int(donation_db_rewards_doc['level'])

                    # put new things into list
                    donation_db_rewards_list.append(donation_db_rewards_doc)

                donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

                # check if reward exists after acquiring the lock and re-fetching data
                reward_exists = False
                for donation_db_rewards_doc in donation_db_rewards_list:
                    if int(level) == donation_db_rewards_doc['level']:
                        reward_exists = True
                        break

                if reward_exists:
                    donation_log_warning(get_ip_address(), session['id'], "Reward already exists, conflict detected after lock")
                    flash('Reward already exists, please use the update or delete function.', 'danger')
                    return redirect(request.url)

                # if reward doesn't exist, proceed with adding it
                donation_log_debug(get_ip_address(), session['id'], "Reward is new")

                image.stream = donation_image_reformat(image)

                donation_log_debug(get_ip_address(), session['id'], "Uploading image to Cloud Storage...")
                # split file name and file extension
                image_name, image_ext = os.path.splitext(image.filename)
                # set image path
                image_path = "donation-rewards/" + str(level) + '.webp'
                # upload the goods
                donation_cloud_storage.child(image_path).put(image)
                # get URL of uploaded file
                image_url = donation_cloud_storage.child(image_path).get_url(None)

                # upload to firestore
                donation_db_ref = donation_db.collection('rewards').document(level)
                donation_db_ref.set({
                    'level': level,
                    'name': name,
                    'description': description,
                    'image_url': image_url,
                    'image_path': image_path,
                })
                # pass a success message
                donation_log_info(get_ip_address(), session['id'], "Image successfully uploaded to Cloud Storage")
                flash('Reward added', 'success')
                return redirect(request.url)

            finally:
                # clear the flag indicating the request is done
                donation_admin_running_flags[userid] = False


    return render_template('donation-admin.html', donation_form=donation_form, donation_db_list=donation_db_list,
                           donation_db_users_list=donation_db_users_list,
                           donation_db_rewards_list=donation_db_rewards_list,
                           donation_db_profanities_list=donation_db_profanities_list,
                           donation_profanities_statistics=donation_profanities_statistics)


# donation-admin to add profanity to filter list
@app.route('/donation-admin-profanities', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_profanities():
    if request.method == 'POST':

        donation_log_debug(get_ip_address(), session['id'], f"Retrieving changes in profanity list...")
        # request profanities from form and split them by commas, put entire thing into a list
        profanity_list = [profanity.strip() for profanity in request.form['profanity'].split(',')]
        donation_log_debug(get_ip_address(), session['id'], f"Profanity list [{profanity_list}]")

        # iterate through each profanity in list and push into firestore
        for profanity in profanity_list:
            donation_db_ref = donation_db.collection('profanities').document(profanity)
            donation_db_ref.set({
                'profanity': profanity,
                'enabled': True,
            })

        donation_log_debug(get_ip_address(), session['id'], "Changes in profanity list saved to Firestore")
        flash('Profanities added to filter list', 'success')
        return redirect(url_for('donation_admin'))


# purge existing comments using applied filiters
@app.route('/donation-admin-profanities-purge')
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_profanities_purge():
    donation_log_debug(get_ip_address(), session['id'], "Purging existing comments")

    # declare count
    removed_count = 0

    # retrieve current list of enabled profanities
    donation_db_profanities_list = []
    donation_db_profanities_docs = donation_db.collection('profanities').stream()
    donation_log_debug(get_ip_address(), session['id'], "Retrieved from profanity collection database")

    # get the documents in donation collection
    donation_collection_ref = donation_db.collection("donation")
    donation_log_debug(get_ip_address(), session['id'], "Retrieved from donation collection database")

    # to update selected profanities to ENABLED
    donation_updates = {
        "comment": '(removed by admin)',
    }

    # initialize batch function
    donation_batch = donation_db.batch()

    for donation_db_profanities_doc in donation_db_profanities_docs:
        # convert to dict
        donation_db_profanities_doc = donation_db_profanities_doc.to_dict()
        # check if enabled or not
        if donation_db_profanities_doc['enabled'] == True:
            # put new things into list
            donation_db_profanities_list.append(donation_db_profanities_doc['profanity'])

    # load our own list of words
    profanity.load_censor_words(donation_db_profanities_list)

    # retrieve list of comments
    donation_log_debug(get_ip_address(), session['id'], "Retrieving from donation collection database")
    donation_db_list = []
    donation_db_docs = donation_db.collection('donation').stream()
    for donation_db_doc in donation_db_docs:
        # convert to dict
        donation_db_doc = donation_db_doc.to_dict()

        if profanity.contains_profanity(donation_db_doc['comment']):
            donation_log_debug(get_ip_address(), session['id'], f"Removed {donation_db_doc['comment']}")
            doc_ref = donation_collection_ref.document(donation_db_doc['donation_id'])
            donation_batch.update(doc_ref, donation_updates)
            removed_count += 1
            donation_log_debug(get_ip_address(), session['id'], f"Removed count: {removed_count}")

    # push commit to Firestore
    donation_log_debug(get_ip_address(), session['id'], "Pushing commit to Firestore...")
    donation_batch.commit()
    donation_log_debug(get_ip_address(), session['id'], "Push success")

    # pass status
    if removed_count == 0:
        donation_log_info(get_ip_address(), session['id'], "0 comments with profanity purged")
        flash('No comments were removed', 'info')
    elif removed_count > 0:
        donation_log_info(get_ip_address(), session['id'], f"{removed_count} comments with profanity purged")
        flash(str(removed_count) + ' comments were removed', 'success')

    return redirect(url_for('donation_admin'))


# donation-admin to update donation
@app.route('/donation-admin-update/<string:donation_id>', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_update(donation_id):
    if request.method == 'POST':

        donation_log_debug(get_ip_address(), session['id'], "Created new donation form")

        # declare donation_details dict
        donation_details = {}
        donation_details['donation_id'] = donation_id
        # get form data from html
        donation_details['amount'] = float(request.form['amount'])
        donation_details['points'] = float(
            request.form['amount']) * 69  # a highly complex algorithm to calculate points
        donation_details['comment'] = request.form['comment']
        donation_details['timestamp_update'] = 'timestamp-update' in request.form

        donation_log_debug(get_ip_address(), session['id'], f"donation_details [{donation_details}]")

        # update timestamp if timestamp-update == True
        if donation_details['timestamp_update'] == True:
            # update firestore FOR DONATION
            donation_db_ref = donation_db.collection('donation').document(str(donation_details['donation_id']))
            donation_db_ref.update({
                'amount': donation_details['amount'],
                'points': donation_details['points'],
                'comment': donation_details['comment'],
                'timestamp': datetime.datetime.now().isoformat(),
                'timestamp_formatted': datetime.datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            })

        # if timestamp_update == False dont include timestamp statements
        elif donation_details['timestamp_update'] == False:
            # update firestore FOR DONATION
            donation_db_ref = donation_db.collection('donation').document(str(donation_details['donation_id']))
            donation_db_ref.update({
                'amount': donation_details['amount'],
                'points': donation_details['points'],
                'comment': donation_details['comment'],
            })

        else:
            # pass another danger message
            donation_log_critical(get_ip_address(), session['id'], "Donation document update: Unknown error occurred")
            flash('Unknown error occurred, please try again.', 'danger')
            return redirect(request.url)

        # pass a success message
        donation_log_debug(get_ip_address(), session['id'], "Donation document updated in Firestore")
        flash('Donation updated', 'success')
        return redirect(url_for('donation_admin'))


# donation-admin to update users
@app.route('/donation-admin-update-users/<string:user_id>', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_update_users(user_id):
    if request.method == 'POST':

        donation_log_debug(get_ip_address(), session['id'], "Created new donation form")

        # declare donation_details_users dict
        donation_details_users = {}
        donation_details_users['user_id'] = user_id
        # get from the radio buttons
        donation_details_users['points_update'] = request.form['points-update-' + donation_details_users['user_id']]

        donation_log_debug(get_ip_address(), session['id'], f"donation_details [{request.form}]]")

        # if admin wants to update points auto
        if donation_details_users['points_update'] == 'True':
            # get the collection
            donation_db_collection = donation_db.collection('donation')
            # do the query
            donation_db_query = donation_db_collection.where('user_id', '==', donation_details_users['user_id'])
            # declare the new points
            donation_details_users['points'] = 0
            # Execute the query and calculate the total points
            donation_log_debug(get_ip_address(), session['id'], "Retrieving from donation collection database...")
            donation_db_docs = donation_db_query.stream()
            for donation_db_doc in donation_db_docs:
                donation_details_users['points'] += donation_db_doc.get('points')

            donation_log_debug(get_ip_address(), session['id'], "Calculating total points...")
            

        elif donation_details_users['points_update'] == 'False':
            # validate form
            if donation_form_validate_users(request.form, donation_details_users['user_id']) == False:
                return redirect(request.url)

            # retrieve the manually entered in points
            donation_details_users['points'] = request.form['points-' + donation_details_users['user_id']]
            donation_log_debug(get_ip_address(), session['id'], f"Manually entered points: {donation_details_users['points']}")

        else:
            # pass another danger message
            donation_log_critical(get_ip_address(), session['id'], "Update user total points: Unknown error occurred")
            flash('Unknown error occurred', 'danger')
            return redirect(request.url)

        # update firestore FOR USERS
        donation_db_ref = donation_db.collection('users').document(str(donation_details_users['user_id']))
        donation_db_ref.update({
            'points': float(donation_details_users['points']),
        })

        # pass a success message
        donation_log_debug(get_ip_address(), session['id'], "Total points updated")
        flash('User updated', 'success')
    return redirect(url_for('donation_admin'))


# donation-admin to update rewards
@app.route('/donation-admin-update-rewards/<int:level>', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_update_rewards(level):

    if request.method == 'POST':

        userid = session['id']

        # check if a process is already running for this user
        if donation_admin_running_flags.get(userid, False):
            session['Error'] = 'Threading'
            flash('Another reward is currently being created/updated, please try again in 30 seconds', 'warning')
            return redirect(request.url)

        if userid not in donation_admin_lock:
            donation_admin_lock[userid] = threading.Lock()

        with donation_admin_lock[userid]:
            # inside this lock set the flag showing something is happening for this user
            donation_admin_running_flags[userid] = True

            try:

                donation_log_debug(get_ip_address(), session['id'], "Created new donation form")

                # declare donation_details_rewards dict
                donation_details_users_rewards = {}
                donation_details_users_rewards['level'] = level

                # get the form data
                donation_details_users_rewards['name'] = request.form['name']
                donation_details_users_rewards['description'] = request.form['description']

                donation_log_debug(get_ip_address(), session['id'], f"donation_details_users_rewards [{request.form}]")

                # request file from form
                image = request.files['img_file']

                # validate form
                if donation_form_validate_rewards == False:
                    return redirect(request.url)

                # check whether a new image has been uploaded, assign a boolean
                if image.filename == '':
                    # if no image has been uploaded, then the filename will be empty string
                    donation_details_users_rewards['new_image'] = False
                else:
                    donation_details_users_rewards['new_image'] = True

                # if new image has been uploaded
                if donation_details_users_rewards['new_image'] == True:

                    # check for varroos in image uploaded
                    if donation_file_check(image) == False:
                        return redirect(request.url)

                    # check if file uploaded is image filetype
                    if donation_image_check(image) == False:
                        return redirect(request.url)

                    # delete the original image first
                    # first retrieve the image path
                    donation_rewards_doc = donation_db.collection('rewards').document(str(level)).get().to_dict()
                    image_path = donation_rewards_doc['image_path']
                    donation_log_debug(get_ip_address(), session['id'], f"Existing image_path [{image_path}]")

                    # then use path to delete image
                    blob = donation_bucket.blob(image_path)
                    blob.delete()
                    donation_log_debug(get_ip_address(), session['id'], "Deleted existing image in Cloud Storage")

                    # reformat the image
                    image.stream = donation_image_reformat(image)

                    # split file name and file extension
                    image_name, image_ext = os.path.splitext(image.filename)
                    # set image path
                    image_path = "donation-rewards/" + str(donation_details_users_rewards['level']) + '.webp'
                    # upload the goods
                    donation_cloud_storage.child(image_path).put(image)
                    donation_log_debug(get_ip_address(), session['id'], "Image uploaded to Cloud Storage")
                    # get url of uploaded file
                    image_url = donation_cloud_storage.child(image_path).get_url(None)

                    # upload to firestore with image details
                    donation_db_ref = donation_db.collection('rewards').document(str(donation_details_users_rewards['level']))
                    donation_db_ref.update({
                        'level': donation_details_users_rewards['level'],
                        'name': donation_details_users_rewards['name'],
                        'description': donation_details_users_rewards['description'],
                        'image_url': image_url,
                        'image_path': image_path,
                    })
                    donation_log_debug(get_ip_address(), session['id'], "Reward document updated in Firestore")

                    # pass a success message
                    donation_log_info(get_ip_address(), session['id'], "Reward successfully updated")
                    flash('Rewards updated', 'success')

                # if no new image has been uploaded
                elif donation_details_users_rewards['new_image'] == False:
                    # upload to firestore without image details
                    donation_db_ref = donation_db.collection('rewards').document(str(donation_details_users_rewards['level']))
                    donation_db_ref.update({
                        'level': donation_details_users_rewards['level'],
                        'name': donation_details_users_rewards['name'],
                        'description': donation_details_users_rewards['description'],
                    })

                    # pass a success message
                    donation_log_info(get_ip_address(), session['id'], "Reward successfully updated")
                    flash('Rewards updated', 'success')

                else:
                    # pass another danger message
                    flash('Unknown error occurred, please try again.', 'danger')
                    return redirect(request.url)

            finally:
                donation_admin_running_flags[userid] = False

    return redirect(url_for('donation_admin'))


# donation-admin to update users
@app.route('/donation-admin-update-profanities', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_update_profanities():
    if request.method == 'POST':

        donation_log_debug(get_ip_address(), session['id'], "Created new donation form")

        # declare database list
        donation_db_list = []
        # declare form data list
        donation_details_profanities = request.form
        # declare dicts for updates
        donation_details_profanities_updates = {}
        # declare list for enable
        donation_details_profanities_enable = []
        # decalre list for disable
        donation_details_profanities_disable = []

        donation_log_debug(get_ip_address(), session['id'], f"donation_details_profanities [{request.form}]")

        # retrieve data
        donation_log_debug(get_ip_address(), session['id'], "Retrieving from profanities collection database")
        donation_db_docs = donation_db.collection('profanities').stream()

        # iterate through all the profanities in firestore
        for donation_db_doc in donation_db_docs:
            # convert to dict
            donation_db_doc = donation_db_doc.to_dict()

            # assume all profanities are not enabled first
            donation_details_profanities_updates[donation_db_doc['profanity']] = False

            # iterate through all enabled profanities in form, for comparison with profanities in firestore
            for profanity in donation_details_profanities:
                # just to take out the csrf token AND search for the profanity
                if profanity != 'csrf_token' and profanity == donation_db_doc['profanity']:
                    # if found then enable it
                    donation_details_profanities_updates[donation_db_doc['profanity']] = True

        # check through the updates dict and put profanities into separate lists
        for profanity in donation_details_profanities_updates:

            # if a profanity is reported to be enabled, append to enable list
            if donation_details_profanities_updates[profanity] == True:
                donation_details_profanities_enable.append(profanity)

            # if a profanity is reported to be disabled, append to disable list
            elif donation_details_profanities_updates[profanity] == False:
                donation_details_profanities_disable.append(profanity)

        # get the documents in profanities collection
        donation_collection_ref = donation_db.collection("profanities")

        # to update selected profanities to ENABLED
        donation_updates = {
            "enabled": True,
        }

        # initialize batch function
        donation_batch = donation_db.batch()

        # stage the changes for selected documents
        for donation_doc in donation_details_profanities_enable:
            doc_ref = donation_collection_ref.document(donation_doc)
            donation_batch.update(doc_ref, donation_updates)

        # push commit to firstore
        donation_log_debug(get_ip_address(), session['id'], "Pushing enabled profanity list to Firestore")
        donation_batch.commit()
        donation_log_info(get_ip_address(), session['id'], "Changes updated successfully")

        # to update selected profanities to DISABLED
        donation_updates = {
            "enabled": False,
        }

        # initialize batch function
        donation_batch = donation_db.batch()

        # stage the changes for selected documents
        for donation_doc in donation_details_profanities_disable:
            doc_ref = donation_collection_ref.document(donation_doc)
            donation_batch.update(doc_ref, donation_updates)

        # push commit to firstore
        donation_log_debug(get_ip_address(), session['id'], "Pushing disabled profanity list to Firestore")
        donation_batch.commit()
        donation_log_info(get_ip_address(), session['id'], "Changes updated successfully")

    return redirect(url_for('donation_admin'))


# donation-admin to delete donation
@app.route('/donation-admin-delete/<string:donation_id>', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_delete(donation_id):
    donation_db.collection('donation').document(donation_id).delete()
    donation_log_debug(get_ip_address(), session['id'], "Donation document deleted")
    flash(donation_id + ' has been successfully deleted.', 'success')
    return redirect(url_for('donation_admin'))


# donation-admin to delete users
@app.route('/donation-admin-delete-users/<string:user_id>', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_delete_users(user_id):
    donation_db.collection('users').document(user_id).delete()
    donation_log_debug(get_ip_address(), session['id'], "Donation user document deleted")
    flash(user_id + ' has been successfully deleted.', 'success')
    return redirect(url_for('donation_admin'))


# donation-admin to delete rewards
@app.route('/donation-admin-delete-rewards/<int:level>', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_delete_rewards(level):
    # convert level from int type to str type, firebase document identifier only accepts string apparently
    level = str(level)  # bruh

    # delete image from cloud storage
    # first retrieve the image path
    donation_rewards_doc = donation_db.collection('rewards').document(str(level)).get().to_dict()
    image_path = donation_rewards_doc['image_path']

    # then use path to delete image
    blob = donation_bucket.blob(image_path)
    blob.delete()

    # lastly delete from firestore rewards collection
    donation_db.collection('rewards').document(level).delete()

    donation_log_debug(get_ip_address(), session['id'], "Donation reward document deleted")
    flash('Reward level ' + level + ' has been successfully deleted.', 'success')
    return redirect(url_for('donation_admin'))


# donation-admin to delete profanities
@app.route('/donation-admin-delete-profanities/<string:profanity>', methods=['POST', 'GET'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def donation_admin_delete_profanities(profanity):
    donation_db.collection('profanities').document(profanity).delete()
    donation_log_debug(get_ip_address(), session['id'], "Donation profanities document deleted")
    flash(profanity + ' has been successfully deleted.', 'success')
    return redirect(url_for('donation_admin'))

'''
Start of Matthew's code
'''
def verify_recaptcha(token):
    secret_key = os.getenv("RECAPTCHA_KEY")
    url = f"https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={token}"
    time.sleep(3)
    try:
        response = requests.post(url)
        response.raise_for_status()
        result = response.json()
        score = result.get("score", 0)
        print(result)
        if result.get("success", False) and score < 0.5:
            return "reCAPTCHA score too low"
        elif result.get("success", False):
            return "success"
        else:
            return "reCAPTCHA verification failed"
    except Exception as e:
        print(f"Error while verifying reCAPTCHA: {e}")
        return "reCAPTCHA verification failed"



@app.route('/RegistrationForm', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@redirect_logged_in
def create_user():
    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        create_user_form = CreateUserForm(formdata=formdata)
    else:
        create_user_form = CreateUserForm()

    if request.method == "POST" and create_user_form.validate():
        token = request.form.get("g-captcha-response")
        result = verify_recaptcha(token)
        if result == "reCAPTCHA score too low":
            flash("reCAPTCHA score too low, try again")
        elif result == "reCAPTCHA verification failed":
            flash("reCAPTCHA verification failed, try again")
        else:
            user = pyreauth.create_user_with_email_and_password(email=create_user_form.email.data,
                                                                password=create_user_form.password.data)
            new_user = {
                'id': user['localId'],
                'username': encrypt(create_user_form.username.data),
                'lower_username': encrypt(create_user_form.username.data.lower()),
                'first_name': encrypt(create_user_form.first_name.data),
                'last_name': encrypt(create_user_form.last_name.data),
                'email': encrypt(create_user_form.email.data),
                'lower_email': encrypt(create_user_form.email.data.lower()),
                'phone_num': encrypt(create_user_form.phone_num.data),
                'address': encrypt(create_user_form.address.data),
                'lower_address': encrypt(create_user_form.address.data.lower()),
                'postal_code': encrypt(create_user_form.postal_code.data),
                'role': "Regular",
                'image_url': "",
                'image_path': "",
                'elixir': 0,
                'lock': False,
                '2FA': False,
                'login_attempts': 0,
                'lock_due_to_attempts': False,
                "otpsecret": generate_secret()
            }

            # Push the new user to the "users" node in the database
            new_user_ref = db_ref.child('users').push(new_user)
            print("User created")
            pyreauth.send_email_verification(user['idToken'])
            login_info("User: " + str(create_user_form.email.data) + " created", request.headers.get('User-Agent'),
                       get_ip_address())
            flash("Email verification sent")
            return redirect(url_for('login'))

    return render_template('registerv2.html', form=create_user_form)


@app.route('/StaffForm', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required('Admin')
@check_lockout
def create_staff():
    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        create_staff_form = CreateStaffForm(formdata=formdata)
    else:
        create_staff_form = CreateStaffForm()
    if request.method == "POST" and create_staff_form.validate():
        token = request.form.get("g-captcha-response")
        result = verify_recaptcha(token)
        if result == "reCAPTCHA score too low":
            flash("reCAPTCHA score too low, try again")
        elif result == "reCAPTCHA verification failed":
            flash("reCAPTCHA verification failed, try again")
        else:
            user = pyreauth.create_user_with_email_and_password(email=create_staff_form.email.data,
                                                                password=create_staff_form.password.data)
            new_user = {
                'id': user['localId'],
                'username': encrypt(create_staff_form.username.data),
                'lower_username': encrypt(create_staff_form.username.data.lower()),  # for case insensitive search
                'first_name': encrypt(create_staff_form.first_name.data),
                'last_name': encrypt(create_staff_form.last_name.data),
                'email': encrypt(create_staff_form.email.data),
                'lower_email': encrypt(create_staff_form.email.data.lower()),
                'phone_num': encrypt(create_staff_form.phone_num.data),
                'role': create_staff_form.role.data,
                'image_url': "",
                'image_path': "",
                'lock': False,
                '2FA': False,
                'login_attempts': 0,
                'lock_due_to_attempts': False,
                "otpsecret": generate_secret()
            }

            # Push the new user to the "users" node in the database
            new_user_ref = db_ref.child('users').push(new_user)

            admin_info("Staff account created for " + str(create_staff_form.email.data) + " with " + str(
                create_staff_form.role.data) + " role." + " by " + str(
                get_user_attribute_encrypted(session['id'], 'email')), session['id'], request.headers.get('User-Agent'),
                       get_ip_address())
            pyreauth.send_email_verification(user['idToken'])


            return redirect(url_for('login'))

    return render_template('StaffRegister.html', form=create_staff_form)



@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@redirect_logged_in
def login():
    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        login_form = LoginForm(formdata=formdata)
    else:
        login_form = LoginForm()

    if request.method == "POST" and login_form.validate():
        token = request.form.get("g-captcha-response")
        result = verify_recaptcha(token)
        if result == "reCAPTCHA score too low":
            print("recaptcha failed")
            flash("reCAPTCHA score too low, try again")
        elif result == "reCAPTCHA verification failed":
            print("recaptcha failed")
            flash("reCAPTCHA verification failed, try again")
        else:
            try:
                user = auth.get_user_by_email(login_form.email.data)
                if not user.disabled and not get_user_id(user.uid, "lock"):
                    try:
                        loginuser = pyreauth.sign_in_with_email_and_password(login_form.email.data,
                                                                             login_form.password.data)
                        if user.email_verified:
                            if get_user_id(loginuser['localId'], '2FA') == True:
                                id = loginuser['localId']
                                session["otpid"] = id
                                update_user_attribute_id(id, 'login_attempts', 0)
                                return redirect(url_for('two_factor'))
                            elif get_user_id(loginuser['localId'], 'enable_2fa_face') == True:
                                id = loginuser['localId']
                                session["faceid"] = id
                                update_user_attribute_id(id, 'login_attempts', 0)
                                return redirect(url_for('two_factor_face'))
                            else:
                                session['id'] = generate_session_id(loginuser['localId'])
                                update_user_attribute_id(loginuser['localId'], 'login_attempts', 0)
                                login_info("User logged in with session id: " + str(session['id']),
                                           request.headers.get('User-Agent'), get_ip_address())
                                return redirect(url_for('dashboard'))
                        else:
                            pyreauth.send_email_verification(loginuser['idToken'])
                            flash("Please verify your email before logging in. Verification email sent")
                    except:
                        login_warning("User failed to login with email: " + str(login_form.email.data),
                                      request.headers.get('User-Agent'), get_ip_address())
                        attempts = get_user_id(user.uid, 'login_attempts')
                        attempts += 1
                        update_user_attribute_id(user.uid, 'login_attempts', attempts)
                        if attempts >= 5:
                            update_user_attribute_id(user.uid, "lock_due_to_attempts", True)
                            login_warning("User locked due to too many failed login attempts with email: " + str(
                                login_form.email.data), request.headers.get('User-Agent'), get_ip_address())
                            auth.update_user(user.uid, disabled=True)
                            lock_last_sent = get_user_id(user.uid, 'lock_last_sent')
                            if isinstance(lock_last_sent, str):
                                lock_last_sent = datetime.fromisoformat(lock_last_sent)
                            if lock_last_sent is None or (datetime.now() - lock_last_sent) >= timedelta(minutes=5):
                                try:
                                    link = url_for("resetpassword", _external=True)
                                    msg = Message("ElectroWizard account locked",sender=os.getenv("EMAIL"),recipients=[user.email])
                                    msg.body = "Your account has been locked for too many failed login attempts please reset your password here to unlock it: {}".format(link)
                                    mail.send(msg)
                                    update_user_attribute_id(user.uid, 'lock_last_sent', datetime.now().isoformat())
                                except:
                                    print("Email failed to send")
                                    login_warning("Email failed to send to user with email: " + str(login_form.email.data),
                                                  request.headers.get('User-Agent'), get_ip_address())
                            flash("Your account is locked for too many failed logins.")
                        else:
                            flash("Invalid email or password. Please try again.")
                else:
                    if get_user_id(user.uid, 'lock_due_to_attempts') == True:
                        flash("Your account is locked for too many failed logins.")
                    else:
                        flash("Your account has been locked for violating our Terms of Service.")
            except:
                # User does not exist or other authentication error
                login_warning("User failed to login with email: " + str(login_form.email.data),
                              request.headers.get('User-Agent'), get_ip_address())
                flash("Invalid email or password. Please try again.")
    return render_template('signin.html', form=login_form)


@app.route('/two_factor', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@redirect_logged_in
def two_factor():
    userid = session["otpid"]
    if not userid:
        return redirect(url_for('login'))
    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        form = TwoFactorForm(formdata=formdata)
    else:
        form = TwoFactorForm()

    if request.method == "POST" and form.validate():
        token = request.form.get("g-captcha-response")
        result = verify_recaptcha(token)
        if result == "reCAPTCHA score too low":
            print("recaptcha failed")
            flash("reCAPTCHA score too low, try again")
        elif result == "reCAPTCHA verification failed":
            print("recaptcha failed")
            flash("reCAPTCHA verification failed, try again")
        else:
            if otpverify(userid, form.otp.data):
                session['id'] = generate_session_id(userid)
                session.pop("otpid", None)
                login_info("User logged in with session id: " + str(session['id']), request.headers.get('User-Agent'),
                           get_ip_address())
                return redirect(url_for('dashboard'))
            else:
                login_warning(
                    "User failed to login via OTP with email: " + str(decrypt(get_user_id(userid, "email"))),
                    request.headers.get('User-Agent'), get_ip_address())
                flash("Invalid code, please try again")
    return render_template('TwoFactor.html', form=form)

@app.route('/two_factor_face', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@redirect_logged_in
def two_factor_face():
    userid = session["faceid"]
    if not userid:
        return redirect(url_for('login'))
    csrf = generate_csrf()
    x = capture_face()
    if x == "quit":
        print("Face verification cancelled")
        session.pop("faceid", None)
        flash("Face verification cancelled")
        try:
            os.remove("faceimage.jpg")
        except:
            pass
        return redirect(url_for('login'))
    if "faceimage.jpg" in os.listdir():
        if detect_face("faceimage.jpg"):
            if verify_face(userid,"faceimage.jpg"):
                session['id'] = generate_session_id(userid)
                session.pop("otpid", None)
                login_info("User logged in with session id: " + str(session['id']), request.headers.get('User-Agent'),
                           get_ip_address())
                print("User logged in")
                try:
                    os.remove("faceimage.jpg")
                except:
                    pass
                return redirect(url_for('dashboard'))
            else:
                login_warning("User failed to login via face with email: " + str(decrypt(get_user_id(userid, "email"))),
                                                                                  request.headers.get('User-Agent'),
                                                                                  get_ip_address())
                flash("Face verification failed. Please login again.")
                try:
                    os.remove("faceimage.jpg")
                except:
                    pass
                return redirect(url_for('login'))
        else:
            login_warning("User failed to login via face with email: " + str(decrypt(get_user_id(userid, "email"))),
                                                                             request.headers.get('User-Agent'),
                                                                             get_ip_address())
            flash("Face verification failed. Please login again.")
            try:
                os.remove("faceimage.jpg")
            except:
                pass
            return redirect(url_for('login'))
    else:
        print("no face")
        flash("Face verification failed. Please login again.")
        return redirect(url_for('login'))
    return render_template('TwoFactor.html', form=form)
@app.route('/registerface', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def registerface():
    x = capture_face()
    if x == "quit":
        flash("Face registration cancelled")
        try:
            os.remove("faceimage.jpg")
        except:
            pass
        return redirect(url_for('profile_v3'))
    if "faceimage.jpg" in os.listdir():
        if register_face("faceimage.jpg"):
            flash("Face registered succesfully!")
            try:
                os.remove("faceimage.jpg")
            except:
                pass
            return redirect(url_for('profile_v3'))
        else:
            flash("Face registration failed", "danger")
            try:
                os.remove("faceimage.jpg")
            except:
                pass
            return redirect(url_for('profile_v3'))
    else:
        flash("Face registration failed", "danger")
        try:
            os.remove("faceimage.jpg")
        except:
            pass
        return redirect(url_for('profile_v3'))


@app.route('/profile-v3', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def profile_v3():
    qrcodeurl = generate_qrurl(get_user_attribute_unencrypted(session['id'], 'otpsecret'))
    user_id = session['id']

    def perform_input_filtering():
        filtered_values = {}
        for key, value in request.form.items():
            filtered_values[key] = filter_input(value)
        request.form = filtered_values

    # Form Validations
    def validate_username(username):
        users_ref = db_ref.child("users")
        lowercase_username = username.lower()
        query_result = users_ref.get()
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_username']:
                    if decrypt(user_data["lower_username"]) == lowercase_username:
                        if username == get_user_attribute_encrypted(session['id'], 'username'):
                            return True
                        else:
                            return False
            except:
                pass
        return True

    def validate_phone_num(phone_num):
        try:
            parsed_phone_num = phonenumbers.parse(phone_num, None)
            if not phonenumbers.is_valid_number(parsed_phone_num):
                return False
            users_ref = db_ref.child("users")
            query_result = users_ref.get()
            for user_id, user_data in query_result.items():
                try:
                    if user_data['phone_num']:
                        if decrypt(user_data["phone_num"]) == phone_num:
                            if phone_num == get_user_attribute_encrypted(session['id'], 'phone_num'):
                                return True
                            else:
                                return False
                except:
                    pass
        except phonenumbers.phonenumberutil.NumberParseException:
            return False
        return True

    def validate_address(address):
        users_ref = db_ref.child("users")
        lowercase_address = address.lower()
        query_result = users_ref.get()
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_address']:
                    if decrypt(user_data["lower_address"]) == lowercase_address:
                        if address == get_user_attribute_encrypted(session['id'], 'address'):
                            return True
                        else:
                            return False
            except:
                pass
        return True

    def validate_postal_code(postal_code):
        users_ref = db_ref.child("users")
        query_result = users_ref.get()
        if postal_code.isdigit() == False:
            return False
        for user_id, user_data in query_result.items():
            try:
                if user_data['postal_code']:
                    if decrypt(user_data["postal_code"]) == postal_code:
                        if postal_code == get_user_attribute_encrypted(session['id'], 'postal_code'):
                            return True
                        else:
                            return False
            except:
                pass

        return True

    def validate_email(email):
        email_pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False
        users_ref = db_ref.child("users")
        query_result = users_ref.get()
        lowercase_email = email.lower()
        for user_id, user_data in query_result.items():
            try:
                if user_data['lower_email']:
                    if decrypt(user_data["lower_email"]) == lowercase_email:
                        if email == get_user_attribute_encrypted(session['id'], 'email'):
                            return True
                        else:
                            return False
            except:
                pass
        return True

    allowed_extensions = {'png', 'jpg', 'jpeg'}
    def is_allowed_image_file(file):
        mimetype = mimetypes.guess_type(file.filename)[0]
        return mimetype is not None and mimetype.startswith('image') and mimetype.split('/')[1] in allowed_extensions

    # get the wtforms profile form for csrf token
    form = ProfileForm(request.form)

    # declare profile_details dict first
    profile_details = {}

    profile_details['user_id'] = session['id']

    if request.method == "POST":
        user_id = session['id']
        form = ProfileForm()
        # perform input filtering
        perform_input_filtering()
        # request file from form
        if 'image_file' in request.files and request.files['image_file'].filename != '':
            if is_allowed_image_file(request.files['image_file']) == False:
                flash("Please submit png, jpg or jpeg image files only")
                return redirect(url_for('profile_v3'))

            profile_details['image'] = request.files['image_file']
            virus = analyse_pfp(profile_details['image'])
            if virus == True:
                flash("Please upload a safe image file")
                return redirect(url_for('profile_v3'))
        profile_details['image'] = request.files['image_file']
        # get filename of image uploaded
        profile_details['image_name'] = profile_details['image'].filename

        # check if new image has been uploaded
        if profile_details['image_name'] == '':
            # if no image has been uploaded, then the filename will be empty string
            profile_details['new_image'] = False
        else:
            profile_details['new_image'] = True

        # if new image has been uploaded
        if profile_details['new_image'] == True:

            # validate the image first
            profile_details['validate_image'] = validate_image(profile_details['image'])

            # delete the original image
            # first retrieve the image path
            profile_details['image_path'] = get_user_attribute_unencrypted(profile_details['user_id'], 'image_path')

            # check if user has image at all
            if profile_details['image_path'] != '':
                # if user has upload image before, the path will NOT be a blank string
                # then use path to delete image
                cloud_storage_delete_image(profile_details['image_path'])

            # validate new image
            if profile_details['validate_image'] == True:

                # upload to image and return image url and path
                profile_details['image_url'], profile_details['image_path'] = cloud_storage_set_image(
                    profile_details['image'], 'profile/' + profile_details['user_id'])
                # uplaod to realtime database with image details
                update_user_attribute_unencrypted(profile_details['user_id'], 'image_url', profile_details['image_url'])
                update_user_attribute_unencrypted(profile_details['user_id'], 'image_path',
                                                  profile_details['image_path'])

            elif profile_details['validate_image'] == False:
                # pass a warning message
                flash('Invalid file type. Only png, jpg, jpeg, and webp are allowed', 'warning')
                return redirect(request.url)

            else:
                flash('Unknown error', 'danger')
                return redirect(request.url, form=form)

        # update the realtime database without image details
        flashes = []  # Define an empty list to store flash messages
        if len(request.form['username']) == 0:
            flash("Username cannot be empty.", "danger")
            flashes.append(('Username cannot be empty.', 'danger'))
        if len(request.form['phone_number']) == 0:
            flash("Phone number cannot be empty.", "danger")
            flashes.append(('Phone number cannot be empty.', 'danger'))
        if len(request.form['address']) == 0:
            flash("Address cannot be empty.", "danger")
            flashes.append(('Address cannot be empty.', 'danger'))
        if len(request.form['postal_code']) == 0:
            flash("Postal code cannot be empty.", "danger")
            flashes.append(('Postal code cannot be empty.', 'danger'))
        if len(request.form['email']) == 0:
            flash("Email cannot be empty.", "danger")
            flashes.append(('Email cannot be empty.', 'danger'))
        if len(request.form["first_name"]) == 0:
            flash("First name cannot be empty.", "danger")
            flashes.append(('First name cannot be empty.', 'danger'))
        if len(request.form["last_name"]) == 0:
            flash("Last name cannot be empty.", "danger")
            flashes.append(('Last name cannot be empty.', 'danger'))

        if not validate_username(request.form['username']):
            flash("Username is already taken.", "danger")
            flashes.append(('Username is already taken.', 'danger'))

        if not validate_phone_num(request.form['phone_number']):
            flash("Invalid phone number or is already taken.", "danger")
            flashes.append(('Invalid phone number.', 'danger'))

        if not validate_address(request.form['address']):
            flash("Invalid address or is already taken.", "danger")
            flashes.append(('Address already exists. Please choose a different one.', 'danger'))

        if not validate_postal_code(request.form['postal_code']):
            flash("Invalid postal code or is already taken.", "danger")
            flashes.append(('Invalid postal code.', 'danger'))

        if not validate_email(request.form['email']):
            flash("Invalid email or is already taken.", "danger")
            flashes.append(('Invalid email.', 'danger'))

        # Check if there are any errors
        if any(flash[1] == 'danger' for flash in flashes):
            print(flashes)
            profile_details['first_name'] = get_user_attribute_encrypted(user_id, "first_name")
            profile_details['last_name'] = get_user_attribute_encrypted(user_id, "last_name")
            profile_details['username'] = get_user_attribute_encrypted(user_id, "username")
            profile_details['phone_number'] = get_user_attribute_encrypted(user_id, "phone_num")
            profile_details['address'] = get_user_attribute_encrypted(user_id, "address")
            profile_details['postal_code'] = get_user_attribute_encrypted(user_id, "postal_code")
            profile_details['image_url'] = get_user_attribute_unencrypted(profile_details['user_id'], 'image_url')
            profile_details['image_path'] = get_user_attribute_unencrypted(profile_details['user_id'], 'image_path')
            profile_details['2FA'] = get_user_attribute_unencrypted(profile_details['user_id'], '2FA')
            profile_details['Face_2FA'] = get_user_attribute_unencrypted(profile_details['user_id'],'enable_2fa_face')
            profile_details['qrcodeurl'] = generate_qrurl(
                get_user_attribute_unencrypted(profile_details['user_id'], 'otpsecret'))
            profile_details['email'] = get_user_attribute_encrypted(profile_details['user_id'], 'email')
            account_warning("User " + str(
                get_user_attribute_encrypted(session['id'], "email")) + " failed to update profile details.",
                            session['id'], request.headers.get('User-Agent'), get_ip_address())

            return render_template("profile-v3.html", profile_details=profile_details, form=form)
        else:
            # Perform the necessary updates and show success flash message

            update_user_attribute_encrypted(profile_details['user_id'], 'first_name', request.form['first_name'])

            update_user_attribute_encrypted(profile_details['user_id'], 'last_name', request.form['last_name'])

            update_user_attribute_encrypted(profile_details['user_id'], 'username', request.form['username'])
            update_user_attribute_encrypted(profile_details['user_id'], 'lower_username',
                                            request.form['username'].lower())

            update_user_attribute_encrypted(profile_details['user_id'], 'phone_num', request.form['phone_number'])

            update_user_attribute_encrypted(profile_details['user_id'], 'address', request.form['address'])
            update_user_attribute_encrypted(profile_details['user_id'], 'lower_address',
                                            request.form["address"].lower())
            update_user_attribute_encrypted(profile_details['user_id'], 'postal_code', request.form['postal_code'])
            if request.form['email'].lower() != get_user_attribute_encrypted(profile_details['user_id'], 'lower_email'):
                update_user_attribute_encrypted(profile_details['user_id'], 'email', request.form['email'])
                update_user_attribute_encrypted(profile_details["user_id"], "lower_email",
                                                request.form['email'].lower())
                set_email(profile_details['user_id'], request.form['email'])
                try:
                    auth.update_user(profile_details['user_id'], email_verified=False)
                    user = auth.get_user(profile_details['user_id'])
                except:
                    flash("Error sending verification email.", "danger")

            status = request.form["2FAStatus"]
            if status == "on":
                update_user_attribute_unencrypted(profile_details['user_id'], '2FA', True)
            else:
                update_user_attribute_unencrypted(profile_details['user_id'], '2FA', False)

            face_status = request.form["Face2FAStatus"]
            if face_status == "on":
                update_user_attribute_unencrypted(profile_details['user_id'], 'enable_2fa_face', True)
            else:
                update_user_attribute_unencrypted(profile_details['user_id'], 'enable_2fa_face', False)

            account_info("User " + str(
                get_user_attribute_encrypted(session['id'], "email")) + " has updated their profile details.",
                         session['id'], request.headers.get('User-Agent'), get_ip_address())
            flash('Great success!', 'success')
            return redirect(url_for('profile_v3'))

    else:
        form = ProfileForm()
        profile_details["email"] = get_user_attribute_encrypted(profile_details['user_id'], 'email')
        profile_details['first_name'] = get_user_attribute_encrypted(user_id, 'first_name')
        profile_details['last_name'] = get_user_attribute_encrypted(profile_details['user_id'], 'last_name')
        profile_details['username'] = get_user_attribute_encrypted(profile_details['user_id'], 'username')
        profile_details['phone_number'] = get_user_attribute_encrypted(profile_details['user_id'], 'phone_num')
        profile_details['address'] = get_user_attribute_encrypted(profile_details['user_id'], 'address')
        profile_details['postal_code'] = get_user_attribute_encrypted(profile_details['user_id'], 'postal_code')
        profile_details['email'] = get_user_attribute_encrypted(profile_details['user_id'], 'email')
        profile_details['image_url'] = cloud_storage_get_profile_image_url_sess(profile_details['user_id'])
        profile_details['image_path'] = get_user_attribute_unencrypted(profile_details['user_id'], 'image_path')
        profile_details['2FA'] = get_user_attribute_unencrypted(profile_details['user_id'], '2FA')
        profile_details['Face_2FA'] = get_user_attribute_unencrypted(profile_details['user_id'], 'enable_2fa_face')
        profile_details['qrcodeurl'] = generate_qrurl(
            get_user_attribute_unencrypted(profile_details['user_id'], 'otpsecret'))

        return render_template("profile-v3.html", form=form, profile_details=profile_details)


@app.route('/resetpassword', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@redirect_logged_in
def resetpassword():
    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        resetpass_form = ResetPassForm(formdata=formdata)
    else:
        resetpass_form = ResetPassForm()

    if request.method == "POST" and resetpass_form.validate():
        token = request.form.get("g-captcha-response")
        result = verify_recaptcha(token)
        if result == "reCAPTCHA score too low":
            print("recaptcha failed")
            flash("reCAPTCHA score too low, try again")
        elif result == "reCAPTCHA verification failed":
            print("recaptcha failed")
            flash("reCAPTCHA verification failed, try again")
        else:
            users_ref = db_ref.child("users")
            query_result = users_ref.get()
            found = False
            for user_id, user_data in query_result.items():
                try:
                    if decrypt(user_data["email"]) == resetpass_form.email.data:
                        found = True
                        break
                except:
                    pass
            if not found:
                login_warning("Invalid email entered for password reset: " + str(resetpass_form.email.data),
                              request.headers.get('User-Agent'), get_ip_address())
                flash("Password reset email sent.")
                return redirect(url_for('login'))
            else:
                id = user_data['id']
                reset_last_sent = get_user_id(id, 'reset_last_sent')
                if isinstance(reset_last_sent, str):
                    reset_last_sent = datetime.fromisoformat(reset_last_sent)
                if reset_last_sent is None or datetime.now() - reset_last_sent >= timedelta(minutes=5):
                    try:
                        time = datetime.now()
                        mailtoken = s.dumps([resetpass_form.email.data, str(time)])
                        link = url_for('resetpass', token=mailtoken, _external=True)
                        msg = Message("ElectroWizard password reset",sender=os.getenv("EMAIL"),recipients=[resetpass_form.email.data])
                        msg.body = "Hi, here is the link to reset your password: {}".format(link)
                        mail.send(msg)
                        login_info("Password reset email sent to " + str(resetpass_form.email.data),
                                   request.headers.get('User-Agent'), get_ip_address())
                        flash("Password reset email sent.")
                        if isinstance(time, datetime):
                            time = time.isoformat()
                        update_user_attribute_id(id, 'reset_last_sent', time)
                        return redirect(url_for('login'))
                    except:
                        flash("Error sending password reset email. Please try again later.")
                        return redirect(url_for('resetpassword'))
                else:
                    flash("Password reset email sent.")
                    return redirect(url_for('login'))
    return render_template('passwordreset.html', form=resetpass_form)


@app.route('/resetpass/<token>', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@redirect_logged_in
def resetpass(token):
    try:
        email, time = s.loads(token, max_age=300)
    except SignatureExpired:
        flash("The password reset link has expired. Please try again.")
        return redirect(url_for('resetpassword'))

    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        setpassword_form = ResetPasswordForm(formdata=formdata)
    else:
        setpassword_form = ResetPasswordForm()

    if request.method == "POST" and setpassword_form.validate():
        try:
            user = auth.get_user_by_email(email)
            user_id = user.uid
        except:
            flash("Invalid email. Please try again.")
            return redirect(url_for('resetpassword'))
        try:
            set_password(user_id, setpassword_form.newpassword.data)
            login_info("Password reset for " + str(email), request.headers.get('User-Agent'), get_ip_address())
            update_user_attribute_id(user_id, 'lock_due_to_attempts', False)
            update_user_attribute_id(user_id, 'login_attempts', 0)
            update_user_attribute_id(user_id, '2FA', False)
            update_user_attribute_id(user_id, 'enable_2fa_face', False)
            auth.update_user(user_id, disabled=False)
            flash("Password reset successful!")
            return redirect(url_for('login'))
        except:
            flash("Error resetting password. Please try again later.")
            login_warning("Error resetting password for " + str(email), request.headers.get('User-Agent'), get_ip_address())
            return redirect(url_for('resetpassword'))
    return render_template('setpassword.html', form=setpassword_form)





@app.route('/users')
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin'])
@check_lockout
def users():
    csrf_token_value = generate_csrf()
    users_ref = db_ref.child("users")
    query_result = users_ref.get()
    users = []
    for user_id, user_data in query_result.items():
        try:
            username = decrypt(user_data.get('username'))
            email = decrypt(user_data.get('email'))
            phone_num = decrypt(user_data.get('phone_num'))
            lock = user_data.get('lock')
            user = {'username': username, 'email': email,
                    'phone_num': phone_num, "lock": lock}
            users.append(user)
        except:
            pass

    return render_template("retrieveUsers.html", data=users, csrf_token=csrf_token_value)


@app.route('/deleteuser/<email>', methods=['POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin'])
@check_lockout
def deleteuser(email):
    if email == get_user_attribute_encrypted(session['id'], "email"):
        return redirect(url_for('users'))
    else:
        delete_user(email)
        admin_info("User: " + email + "deleted by " + str(get_user_attribute_encrypted(session['id'], "email")),
                   session['id'], request.headers.get('User-Agent'), get_ip_address())
    return redirect(url_for('users'))


@app.route('/lockuser/<email>', methods=['POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin'])
@check_lockout
def lockuser(email):
    if email == get_user_attribute_encrypted(session['id'], "email"):
        return redirect(url_for('users'))
    else:
        lock(email)
        admin_info("User: " + str(email) + "locked by " + str(get_user_attribute_encrypted(session['id'], "email")),
                   session['id'], request.headers.get('User-Agent'), get_ip_address())

    return redirect(url_for('users'))


@app.route('/unlockuser/<email>', methods=['POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin'])
@check_lockout
def unlockuser(email):
    if email == get_user_attribute_encrypted(session['id'], "email"):
        return redirect(url_for('users'))
    else:
        unlock(email)
        admin_info("User: " + str(email) + " unlocked by " + str(get_user_attribute_encrypted(session['id'], "email")),
                   session['id'], request.headers.get('User-Agent'), get_ip_address())

    return redirect(url_for('users'))


@app.route("/changepassword", methods=["GET", "POST"])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def changepassword():
    user_id = get_user_attribute_unencrypted(session['id'], "id")
    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        change_password_form = ChangePasswordForm(formdata=formdata)
    else:
        change_password_form = ChangePasswordForm()
    if request.method == "POST" and change_password_form.validate():
        try:
            pyreauth.sign_in_with_email_and_password(get_user_attribute_encrypted(session['id'], "email"),
                                                     change_password_form.currentpassword.data)
            set_password(user_id, change_password_form.newpassword.data)
            print("password changed")
            flash("Password changed successfully!")
            account_info(
                "User: " + str(get_user_attribute_encrypted(session['id'], "email")) + " changed their password.",
                session['id'], request.headers.get('User-Agent'), get_ip_address())
            return redirect(url_for('changepassword'))
        except:
            flash("Invalid password. Please try again.")
            account_warning("User: " + str(
                get_user_attribute_encrypted(session['id'], "email")) + " failed to change their password.",
                            session['id'], request.headers.get('User-Agent'), get_ip_address())
    return render_template("changepassword.html", form=change_password_form)


@app.route("/deleteaccount", methods=["GET", "POST"])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def deleteaccount():
    if request.method == "POST":
        filtered_form_data = {key: filter_input(value) for key, value in request.form.items()}
        formdata = MultiDict(filtered_form_data)
        delete_account_form = DeleteAccountForm(formdata=formdata)
    else:
        delete_account_form = DeleteAccountForm()
    if request.method == "POST" and delete_account_form.validate():
        try:
            user_id = get_user_attribute_unencrypted(session['id'], "id")
            pyreauth.sign_in_with_email_and_password(get_user_attribute_encrypted(user_id, "email"),
                                                     delete_account_form.password.data)
            delete_user(get_user_attribute_encrypted(user_id, "email"))
            flash("Account deleted successfully!")
            account_info("User: " + str(get_user_attribute_encrypted(user_id, "email")) + " deleted their account.",
                         session['id'], request.headers.get('User-Agent'), get_ip_address())
            return redirect(url_for('logout'))
        except:
            flash("Invalid password. Please try again.")
            account_warning(
                "User: " + str(get_user_attribute_encrypted(user_id, "email")) + " failed to delete their account.",
                session['id'], request.headers.get('User-Agent'), get_ip_address())
    return render_template("deleteaccount.html", form=delete_account_form)

'''
End of Matthew's code
'''

@app.route('/scan', methods=['GET', 'POST'])
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def upload_electricBill():
    # Works only for senoko energy for now
    maxfilesize = 1024 * 1024 * 5  # 5mb
    donation_form = DonationForm(request.form)
    billdb = donation_db.collection('electricbill').document()
    userid = session['id']
    if user_running_flags.get(userid, False):
        session['Error']='Threading'
        return redirect(url_for('failedsubmission'))
    user_running_flags[userid] = True
    if userid not in userlocks:
        userlocks[userid]=threading.Lock()
    with userlocks[userid]:
        try:
            if request.method == 'POST':
                hash_value = request.form.get('hash_value')
                file = request.files['img_file']
                if verify_hash(file, hash_value):
                    passhash=True
                else:
                    session['Error'] = 'Tampered'
                    bill_critical('User file was tampered with.',session['id'])
                    return redirect(url_for('failedsubmission'))
                if 'expirerate' in session and time.time() < session['expirerate']:
                    session['submitted'] = session['submitted'] + 1
                    if session['submitted'] > 5:
                        bill_critical('User has tried to submit multiple times despite being rate limited',session['id'])
                    session['Error'] = 'RateLimited'
                    return redirect(url_for('failedsubmission'))
                if 'expirerate' in session and time.time() > session['expirerate']:
                    session.pop('expirerate', None)
                    session.pop('submitted',None)
                if 'expirerate' not in session:
                    session['expirerate'] = time.time() + 10
                    session['submitted'] = 0
                if file and file.content_length > maxfilesize:
                    session['Error'] = 'Filesize'
                    bill_failed('User has failed to submit their bill.', session['id'], session.get('Error'))
                    return redirect(url_for('failedsubmission'))
                target_keywords = ['Energy charge']
                check = VirusTotalPDF.scan_file(file)
                if check[1] == 'Unsafe':
                    session['Error']=check[1]
                    bill_critical('User tried submitting an unsafe file',session['id'])
                    return redirect(url_for('failedsubmission'))
                if check[1] == 'Safe':
                    bill_info(
                        "User " + str(get_user_attribute_encrypted(session['id'], "email")) + " has submitted their bill.",
                        session['id'], request.headers.get('User-Agent'), get_ip_address())
                    numbers = Billscanning.scan_pdf_for_keywords(file, target_keywords)
                    if numbers[2] == True:
                        consumptionlist = numbers[0]
                        billdates = numbers[1]
                        period = Billscanning.checkdaterange(billdates)
                        monthperiod = period[0]
                        yearperiod = period[1]
                        confirmationperiod = period[2]
                        db_list = []
                        db_docs = donation_db.collection('electricbill').where('UserID', '==', session['id']).stream()

                        for i in db_docs:
                            # convert to dict
                            db_list.append(i.to_dict())
                        duplicatedperiod = Billscanning.checkbillhistory(monthperiod, yearperiod,db_list)  # Comment this line until the line below duplicatedperiod
                        most_recent_doc = None
                        most_recent_timestamp = None

                        for doc in db_list:
                            timestamp = doc['timestamp']
                            if timestamp is not None:
                                if most_recent_timestamp is None or timestamp > most_recent_timestamp:
                                    most_recent_timestamp = timestamp
                                    most_recent_doc = doc
                        try:
                            streak = Billscanning.checkstreak(most_recent_doc, period[4])
                        except:
                            streak = None
                        if duplicatedperiod == True:
                            session['Error'] = 'Duplicate'
                            return redirect(url_for('failedsubmission'))

                        if confirmationperiod == False:
                            session['CurrentDateRange'] = period[3]
                            session['UserDateRange'] = monthperiod
                            session['Error'] = 'Date'
                            return redirect(url_for('failedsubmission'))
                        userelectric = Billscanning.energycalc(consumptionlist)
                        elixir = round(userelectric / 5)
                        billdb.set({
                            'UserID': session['id'],
                            'Username': get_user_attribute_encrypted(session['id'], 'username'),
                            'Company': 'Senoko',
                            'Consumption': userelectric,
                            'elixir': elixir,
                            'timestamp': datetime.now().isoformat(),
                            'timestamp_formatted': datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
                            'Period': monthperiod,
                            'Year': yearperiod,
                            'MonthCheck': period[4],
                            'Streak':streak
                        })
                        elixirs = get_user_attribute_unencrypted(session['id'],'elixir')
                        update_user_attribute_unencrypted(session['id'],'elixir',elixirs+elixir)
                    else:
                        session['Error'] = 'Company'
                        bill_failed('User has failed to submit their bill.', session['id'], session.get('Error'))
                        return redirect(url_for('failedsubmission'))
                    return redirect(url_for('retrievehistory'))
                else:
                    session['Error'] = check[1]
                    bill_failed('User has failed to submit their bill.', session['id'], session.get('Error'))
                    return redirect(url_for('failedsubmission'))
        finally:
            user_running_flags[userid]=False
    return render_template('bill-scan.html', form=donation_form)
def verify_hash(file, expected_hash):
    # Calculate the hash of the uploaded file
    calculated_hash = calculate_file_hash(file)

    # Compare the calculated hash with the expected hash
    return calculated_hash == expected_hash

def calculate_file_hash(file):
    hash_object = hashlib.sha256()
    chunk_size = 8192  # Process the file in chunks

    while True:
        chunk = file.read(chunk_size)
        if not chunk:
            break
        hash_object.update(chunk)

    return hash_object.hexdigest()


@app.route('/failedsubmission')
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def failedsubmission():
    message = session.get('Error')
    currentaccept = 0
    userdate = 0
    if message == 'Date':
        currentaccept = session.get('CurrentDateRange')
        userdate = session.get('UserDateRange')
    # work on the fact of duplicated values in the db tmr the error messages
    return render_template('bill-failed.html', data=message, currentaccept=currentaccept,
                           userdate=userdate)


@app.route('/submissionhistory')
@limiter.limit("10/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def retrievehistory():
    db_list = []

    # get all of user documents from donation collection
    username = get_user_attribute_encrypted(session['id'], 'username')
    db_docs = donation_db.collection('electricbill').where('Username', '==', username).stream()

    for i in db_docs:
        # convert to dict
        db_list.append(i.to_dict())

    # function for graphing
    x = []
    y = []
    for i in db_list:
        months = i['Period']
        x.append(months)
        consumption = i['Consumption']
        y.append(float(consumption))

    # Create a line graph
    fig, ax = plt.subplots(facecolor='white')  # Set the facecolor to black
    ax.plot(x, y)
    ax.set_xlabel('Month Period')
    ax.set_ylabel('Electrical consumption (Kwh)')
    ax.set_title('Electricity graph')

    # Save the graph image to a BytesIO object
    image_stream = io.BytesIO()
    plt.savefig(image_stream, format='png')
    image_stream.seek(0)

    # Encode the image as a Base64 string
    image_base64 = base64.b64encode(image_stream.getvalue()).decode('utf-8')
    # default sort by date
    return render_template('bill-submissions.html', bills=db_list, graph=image_base64)

@app.errorhandler(500)
def internal_server_error(e):
    session['Error'] = 'VUnexpected'
    return redirect(url_for('failedsubmission'))

@app.route('/bill-leaderboard')
@limiter.limit("10/second", override_defaults=False)
def billleader():
    try:
        db_list = []
        currentperiod = Billscanning.checkcurrentleaderboard()
        month_period = currentperiod[1]
        currentyear = currentperiod[0]
        collection_ref = donation_db.collection('electricbill').where('Period','==', 'Mar-Apr').where('Year','==','2023-2023')
        collection_ref = donation_db.collection('electricbill')
        collection_ref = donation_db.collection('electricbill').where('Period','==', 'Mar-Apr').where('Year','==','2023-2023')
        query_snapshot = collection_ref.get()
        documents = [doc.to_dict() for doc in query_snapshot]
        sorted_documents = sorted(documents, key=lambda doc: doc.get('Consumption', 0), reverse=True)
        for i, doc in enumerate(sorted_documents):
            doc_ref = collection_ref.document(doc.id)
            doc_ref.update({
                'Rank': i + 1
            })
        try:
            collection_ref = donation_db.collection('electricbill').where('Period','==', month_period).where('Year','==',currentyear)#/// use this for final presentation only or when you have a lot of data already
            query_snapshot = collection_ref.get()

            documents = [doc for doc in query_snapshot]
            sorted_documents = sorted(documents, key=lambda doc: doc.get('Consumption'), reverse=False)
            for i, doc in enumerate(sorted_documents):
                doc_ref = donation_db.collection('electricbill').document(doc.id)
                doc_ref.update({
                    'Rank': i + 1
                })
        # query_snapshot = collection_ref.where('Period','==', 'Mar-Apr').where('Year','==','2023-2023').get()
        # count = 0
        # for doc in query_snapshot:
        #     count += 1
        #     doc_ref = collection_ref.document(doc.id)
        #     doc_ref.update({
        #         'CurrentRank': count
        #     })
        # collection_ref = donation_db.collection('electricbill').where('Period','==', month_period).where('Year','==',currentyear)/// use this for final presentation only or when you have a lot of data already
        # query_snapshot = collection_ref.get()
        # count = 0
        # for doc in query_snapshot:
        #     count += 1
        #     doc_ref = query_snapshot.document(doc.id)
        #     doc_ref.update({
        #         'CurrentRank':count
        #     })
        except:
            redirect(url_for('failedsubmission'))
    except:
        redirect(url_for('failedsubmission'))

        # # for doc in sorted_documents: #Maybe might need if the top one fails but otherwise its not needed
        # #     print(doc['specific_value'])
        # db_docs = donation_db.collection('electricbill').where('Period','==', 'Mar-Apr').where('Year','==','2023-2023').stream()
        # for doc in db_docs:
        #     db_list.append(doc.to_dict())
    return render_template('bill-leaderboard.html', documents=sorted_documents,date=month_period)


@app.route('/bill-leaderboard/<period>/<year>')
@limiter.limit("10/second", override_defaults=False)
def periodfilter(period, year):
    db_list = []
    checkedperiod = period
    yearperiod = year
    db_docs = donation_db.collection('electricbill').where('Period', '==', checkedperiod).where('Year', '==',
                                                                                                yearperiod).get()
    documents = [doc for doc in db_docs]
    sorted_documents = sorted(documents, key=lambda doc: doc.get('Consumption'), reverse=False)
    return render_template('bill-leaderboard.html', documents=sorted_documents)

@app.route('/referral',methods=['GET', 'POST'])
@verify_session
@refresh_session
@check_lockout
@limiter.limit("10/second", override_defaults=False)
def submitreferral():
    currentdb = donation_db.collection('referral_code').document(session['id']).get()
    donation_form = DonationForm(request.form)
    if currentdb.exists:
        referral_data = currentdb.to_dict()
        referral_code = referral_data.get('code')
    else:
        expiry_date = datetime.now() + timedelta(days=30)  # Adjust expiry duration
        referral_code = generate_unique_referral_code()
        if referral_code == 'Failed':
            session['Error'] = 'Unexpected'
            return redirect(url_for('failedsubmission'))
        referral_code = encrypt_referral_code(referral_code,os.getenv('ENCRYPTION_KEY'))
        doc_ref = donation_db.collection('referral_code').document(session['id'])
        doc_ref.set({
            'code': referral_code,
            'expiryDate': expiry_date,
            'userid': session['id']
        })
    if request.method == 'POST':
        if 'expired' in session and time.time() < session['expired']:
            session['submit'] = session['submit'] + 1
            if session['submit'] > 5:
                bill_critical("User has been trying to submit many times when rate limited with session id: ", session['id'])
            session['Error'] = 'RateLimit'
            return redirect(url_for('failedsubmission'))
        if 'expired' in session and time.time() > session['expired']:
            session.pop('expired', None)
            session.pop('submit', None)
        if 'expired' not in session:
            session['expired'] = time.time() + 60
            session['submit'] = 0
        if get_user_attribute_unencrypted(session['id'],'Referral') == False:
            refcodes = request.form.get('img_file')
            docid = ''
            referdb = donation_db.collection('referral_code').stream()
            for doc in referdb:
                doc_data = doc.to_dict()
                ref_code = doc_data.get('code')
                try:
                    if decrypt_referral_code(ref_code,os.getenv('ENCRYPTION_KEY'))==refcodes:
                        docid = doc.id
                except:
                    pass
            if docid == '':
                session['Error'] = 'Used'
                return redirect(url_for('failedsubmission'))
            if docid == session['id']:
                session['Error'] = 'Sameuser'
                return redirect(url_for('failedsubmission'))
            update_user_attribute_unencrypted(session['id'], 'elixir',get_user_attribute_unencrypted(session['id'], 'elixir') + 30)
            update_user_attribute_unencrypted(docid, 'elixir',get_user_attribute_unencrypted(docid, 'elixir') + 10)
            update_user_attribute_unencrypted(session['id'], 'Referral', True)
            donation_db.collection('referral_code').document(docid).delete()
            return render_template('refSuccess.html')
        elif get_user_attribute_unencrypted(session['id'],'Referral')==True:
            session['Error'] = 'Referred'
            return redirect(url_for('failedsubmission'))
    referral_code = decrypt_referral_code(referral_code, os.getenv('ENCRYPTION_KEY'))
    return render_template('referral.html',form=donation_form,refcode=referral_code)

# @app.route('/generatecode')
# @verify_session
# @refresh_session
# @check_lockout
# @limiter.limit("10/second", override_defaults=False)
# def generatereferral():
#     currentdb = donation_db.collection('referral_code').document(session['id']).get()
#     donation_form = DonationForm(request.form)
#     if currentdb.exists:
#         referral_data = currentdb.to_dict()
#         referral_code = referral_data.get('code')
#     else:
#         expiry_date = datetime.now() + timedelta(days=30)  # Adjust expiry duration
#         referral_code = generate_unique_referral_code()
#         if referral_code == 'Failed':
#             session['Error'] = 'Unexpected'
#             return redirect(url_for('failedsubmission'))
#         referral_code = encrypt_referral_code(referral_code,os.getenv('ENCRYPTION_KEY'))
#         doc_ref = donation_db.collection('referral_code').document(session['id'])
#         doc_ref.set({
#             'code': referral_code,
#             'expiryDate': expiry_date,
#             'userid': session['id']
#         })
#     referral_code=decrypt_referral_code(referral_code,os.getenv('ENCRYPTION_KEY'))
#     return render_template('referral.html',refcode=referral_code,form=donation_form)

def generate_referral_code(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def is_referral_code_unique(code):
    query_ref = donation_db.collection('referral_code').where('code', '==', code).limit(1)
    matching_referrals = query_ref.stream()
    return not any(matching_referrals)

def generate_unique_referral_code(length=6, max_attempts=100):
    for _ in range(max_attempts):
        code = generate_referral_code(length)
        if is_referral_code_unique(code):
            return code
    return 'Failed'


# Zy start

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/store', methods=['GET', 'POST'])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def store():
    id = session['id']
    elixir = get_user_attribute_unencrypted(id, 'elixir')

    product_db_list = []

    # get all documents from donation collection
    product_db_docs = donation_db.collection('product').stream()
    for product_db_doc in product_db_docs:
        # convert to dict
        product_db_list.append(product_db_doc.to_dict())

    return render_template('store.html', elixir=elixir, product_db_list=product_db_list)


@app.route('/productform', methods=['GET', 'POST'])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin', 'Product Manager'])
@check_lockout
def create_product():

    csrf_token_value = generate_csrf()
    error_message = None
    name_error_message = None
    price_error_message = None

    if request.method == "POST":
        last_product_id = 0
        product_ref = donation_db.collection('product')
        query = product_ref.order_by('product_id', direction=firestore.Query.DESCENDING).limit(1)
        product_docs = query.stream()
        for doc in product_docs:
            last_product_id = doc.to_dict()['product_id']
        new_product_id = int(last_product_id) + 1

        product_name = html.escape(request.form.get('product_name'))
        product_price = html.escape(request.form.get('product_price'))
        img_file = request.files['img_file']

        if not product_name or not product_price or not img_file:
            error_message = "All fields are required"
        elif len(product_name) > 50:
            name_error_message = "Product name cannot exceed 50 characters."
        elif not re.match(r'^[\w\s.,\-\'"!?()]+$', product_name):
            name_error_message = "Product name contains invalid characters."
        else:
            # if donation_file_check(img_file) == False:
            #     return redirect(request.url)
            if donation_image_check(img_file) == False:
                return redirect(request.url)
            else:
                re_image_file = mission_image_reformat(img_file)
                image_url, image_path = cloud_storage_set_image_mission(re_image_file,
                                                                        "productImage/" + str(new_product_id))
            try:
                product_price = int(product_price)
                if product_price < 0 or product_price > 10000:
                    price_error_message = "Product price must be between 0 and 10000 and must be integer"
                else:
                    donation_db_ref = donation_db.collection('product').document(str(new_product_id))
                    # session variables
                    donation_db_ref.set({
                        'product_id': str(new_product_id),
                        'product_name': str(product_name),
                        'product_price': str(product_price),
                        'path': str(image_path),
                        'url': str(image_url)
                    })
                    return redirect(url_for('store'))
            except ValueError:
                price_error_message = "Product price must be a valid number."



        return render_template('storeadmin.html', error_message=error_message, price_error_message=price_error_message,
                               name_error_message=name_error_message, csrf_token=csrf_token_value)

    return render_template('storeadmin.html', csrf_token=csrf_token_value)
    # , error_message = None, , price_error_message = None, name_error_message = None

elixir_locks = {}
@app.route('/redeem/<string:product_id>/', methods=['GET', 'POST'])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def redeem(product_id):
    id = session['id']
    elixir = int(get_user_attribute_unencrypted(id, 'elixir'))

    if id not in elixir_locks:
        elixir_locks[id] = threading.RLock()

    def process_redeem(id, elixir, product_id):
        with elixir_locks[id]:

            product_ref = donation_db.collection('product')
            query = product_ref.where('product_id', '==', product_id)
            product_docs = query.stream()
            price = 0
            for doc in product_docs:
                doc_data = doc.to_dict()
                price = int(doc_data['product_price'])
                if elixir >= price:
                    new_elixir = elixir - price
                    update_user_attribute_unencrypted(id, 'elixir', new_elixir)
                    return price

            return None

    price = process_redeem(id, elixir, product_id)
    if price is None:
        return render_template('storevalidation.html')
    else:
        return render_template('store-success.html', price=price)


@app.route('/mission', methods=['GET', 'POST'])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def mission():
    id = session['id']
    elixir = get_user_attribute_unencrypted(id, 'elixir')
    user_id = get_user_attribute_unencrypted(session['id'], 'id')
    email = get_user_attribute_encrypted(id, 'email')
    mission_db_list = []

    current_time = datetime.now()
    # get all documents from donation collection
    mission_db_docs = donation_db.collection('mission_user').stream()
    for mission_db_doc in mission_db_docs:
        # convert to dict
        mission_data = mission_db_doc.to_dict()
        mission_time_with_nanoseconds = mission_data['missiontime']
        mission_email = mission_data['email']
        mission_status = mission_data['status']

        year = mission_time_with_nanoseconds.year
        month = mission_time_with_nanoseconds.month
        day = mission_time_with_nanoseconds.day
        hour = mission_time_with_nanoseconds.hour
        minute = mission_time_with_nanoseconds.minute
        second = mission_time_with_nanoseconds.second

        # Create a regular datetime object
        mission_time = datetime(year, month, day, hour, minute, second)
        if mission_time < current_time and mission_email == email and mission_status == 'unsubmitted':
            mission_db_list.append(mission_data)

    mission_user_ref = donation_db.collection('mission_user')
    approved_query = mission_user_ref.where('status', '==', 'approved')
    approved_docs = approved_query.stream()
    approved_list = []
    total_reward = 0
    for doc in approved_docs:
        total_reward += doc.get('missionreward')
        doc_data = doc.to_dict()
        approved_list.append(doc_data)

    rejected_query = mission_user_ref.where('status', '==', 'rejected')
    rejected_docs = rejected_query.stream()
    rejected_list = []
    for doc in rejected_docs:
        doc_data = doc.to_dict()
        rejected_list.append(doc_data)

    encrypted_user_id = encrypt(user_id)

    csrf_token_value = generate_csrf()

    return render_template('mission.html', elixir=elixir, mission_db_list=mission_db_list,
                           encrypted_user_id=encrypted_user_id, approved_list=approved_list, total_reward=total_reward,
                           csrf_token=csrf_token_value, rejected_list=rejected_list)


@app.route('/mission-form', methods=['GET', 'POST'])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin', 'Mission Manager'])
@check_lockout
def create_mission():
    create_mission_form = CreateMissionForm(request.form)
    if request.method == 'POST' and create_mission_form.validate():
        mission_time = datetime.strptime(create_mission_form.mission_time.data, '%Y-%m-%dT%H:%M')

        # Get the last mission ID from Firestore
        last_mission_id = 0
        mission_ref = donation_db.collection('mission').order_by('missionid',
                                                                 direction=firestore.Query.DESCENDING).limit(1)
        for doc in mission_ref.stream():
            last_mission_id = doc.to_dict()['missionid']

        # Increment the mission ID for the new mission
        new_mission_id = last_mission_id + 1

        donation_db_ref = donation_db.collection('mission').document(str(new_mission_id))
        # session variables
        donation_db_ref.set({
            'missionid': new_mission_id,
            'missionname': create_mission_form.mission_name.data,
            'missionreward': create_mission_form.mission_reward.data,
            'missionrequirement': create_mission_form.mission_requirement.data,
            'missiontime': mission_time,
        })

        users_ref = db_ref.child('users')
        users_snapshot = users_ref.get()
        for user_key, user_data in users_snapshot.items():
            encrypted_email = user_data.get('email')
            try:
                user_id = user_data.get('id')
                user_email = decrypt(encrypted_email)
                new_mission_user_id = f"{new_mission_id} {user_email}"
                mission_user_ref = donation_db.collection('mission_user').document(new_mission_user_id)
                mission_user_ref.set({
                    'mission_user_id': new_mission_user_id,
                    'missionid': new_mission_id,
                    'email': user_email,
                    'missionname': create_mission_form.mission_name.data,
                    'missionreward': create_mission_form.mission_reward.data,
                    'missionrequirement': create_mission_form.mission_requirement.data,
                    'missiontime': mission_time,
                    'status': 'unsubmitted',
                    'path': None,
                    'url': None,
                    'rejection_reason': None,
                    'user_id': user_id,
                })
            except Exception as e:
                print(f"Error decrypting Email: {e}")

        return redirect(url_for('mission'))

    return render_template('missionadmin.html', create_mission_form=create_mission_form)


@app.route("/missionevidence/<missionid>/", methods=["GET", "POST"])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def mission_evidence(missionid):
    user_id = get_user_attribute_unencrypted(session['id'], 'id')
    id = session['id']
    email = get_user_attribute_encrypted(id, 'email')

    mission_evidence_form = MissionEvidenceForm()

    if request.method == "POST" and mission_evidence_form.validate_on_submit():
        image_file = mission_evidence_form.mission_evidence.data

        # if donation_file_check(image_file) == False:
        #     return redirect(request.url)
        if donation_image_check(image_file) == False:
            return redirect(request.url)
        else:
            target_mission_user_id = f"{missionid} {email}"
            print(target_mission_user_id)

            mission_user_ref = donation_db.collection('mission_user')

            query = mission_user_ref.where('mission_user_id', '==', target_mission_user_id)

            mission_user_docs = query.stream()

            re_image_file = mission_image_reformat(image_file)
            image_url, image_path = cloud_storage_set_image_mission(re_image_file,
                                                                    "missionEvidence/" + target_mission_user_id)

            for doc in mission_user_docs:
                doc_ref = mission_user_ref.document(doc.id)
                doc_ref.update({
                    'path': image_path,
                    'url': image_url,
                    'status': 'uncheck',
                })

            # donation_db_ref.set({
            #     'evidence_id': new_evidence_id,
            #     'missionid': missionid,
            #     'missionreq': mission_req,
            #     'missionname': mission_name,
            #     'missionreward': mission_reward,
            #     'userid': str(user_id),
            #     'userevidence_url': image_url,
            #     'userevidence_path': image_path,
            # })

            # donation_db_ref.update({"userevidence_url": image_url})
            # donation_db_ref.update({"userevidence_path": image_path})

        return redirect(url_for("mission"))

    return render_template("mission-evidence.html", form=mission_evidence_form, missionid=missionid)


@app.route("/mission-evidence-check", methods=["GET", "POST"])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin', 'Mission Manager'])
@check_lockout
def mission_evidence_check():
    id = session['id']
    uncheck_list = []
    mission_user_ref = donation_db.collection('mission_user')
    query = mission_user_ref.where('status', '==', 'uncheck')
    mission_user_docs = query.stream()

    for doc in mission_user_docs:
        doc_data = doc.to_dict()
        uncheck_list.append(doc_data)

    return render_template("mission-admin-check.html", uncheck_list=uncheck_list)


@app.route("/missionapprove/<mission_user_id>", methods=["GET", "POST"])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin', 'Mission Manager'])
@check_lockout
def missionapprove(mission_user_id):
    mission_user_ref = donation_db.collection('mission_user')
    query = mission_user_ref.where('mission_user_id', '==', mission_user_id)
    print(mission_user_id)
    mission_user_docs = query.stream()

    for doc in mission_user_docs:
        doc_ref = mission_user_ref.document(doc.id)
        doc_ref.update({
            'status': 'approved',
        })
        print(doc)

    return redirect("/mission-evidence-check")

@app.route("/mission_claim", methods=["POST"])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@check_lockout
def mission_claim():
    total_reward = request.form.get('total_reward')
    encrypted_user_id = request.form.get('encrypted_user_id')
    user_id = decrypt(encrypted_user_id)
    elixir = get_user_id(user_id, 'elixir')
    newelixir = elixir + int(total_reward)
    update_user_attribute_id(user_id, "elixir", newelixir)

    mission_user_ref = donation_db.collection('mission_user')
    query = mission_user_ref.where('user_id', '==', user_id).where('status', "==", "approved")
    mission_user_docs = query.stream()

    for doc in mission_user_docs:
        doc_ref = mission_user_ref.document(doc.id)
        doc_ref.update({
            'status': 'claimed',
        })

    return redirect("mission")

# @app.route("/missionreject/<mission_user_id>", methods=["GET", "POST"])
# def missionreject(mission_user_id):
#     mission_user_ref = donation_db.collection('mission_user')
#     query = mission_user_ref.where('mission_user_id', '==', mission_user_id)
#     mission_user_docs = query.stream()
#
#     for doc in mission_user_docs:
#         doc_ref = mission_user_ref.document(doc.id)
#         doc_ref.update({
#             'status': 'rejected',
#         })
#
#     return redirect("mission-evidence-check")


@app.route('/mission_reject_form/<mission_user_id>', methods=['GET', 'POST'])
@limiter.limit("20/second", override_defaults=False)
@verify_session
@refresh_session
@roles_required(['Admin', 'Mission Manager'])
@check_lockout
def mission_reject_form(mission_user_id):
    create_rejection_form = CreateRejectionForm(request.form)
    if request.method == 'POST' and create_rejection_form.validate():

        rejection_reason = create_rejection_form.rejection_reason.data

        mission_user_ref = donation_db.collection('mission_user')
        query = mission_user_ref.where('mission_user_id', '==', mission_user_id)
        mission_user_docs = query.stream()

        for doc in mission_user_docs:
            doc_ref = mission_user_ref.document(doc.id)
            doc_ref.update({
                'status': 'rejected',
                'rejection_reason':rejection_reason,
            })

        return redirect('/mission-evidence-check')

    return render_template('mission_reject_form.html', create_rejection_form=create_rejection_form, mission_user_id=mission_user_id)




# Zy end


@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, 'robots.txt')


if __name__ == '__main__':

    name = "EWiz"

    # if http is True, then no ssl cert
    if https == True:
        app.run(debug=False, host=host, port=port, ssl_context=('ssl/certificate.crt', 'ssl/private.key'))
    # if http is False, then use ssl cert
    elif https == False:
        app.run(debug=False, host=host, port=port)
    # if problem then my bad
    else:
        print("rip")
