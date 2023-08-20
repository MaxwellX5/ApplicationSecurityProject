# firebase libraries
import os
from dotenv import load_dotenv

load_dotenv()

import firebase_admin
from firebase_admin import credentials, db, firestore, auth, storage

# initialize firebase connection
# use service account key to authenticate app
cred = credentials.Certificate("serviceAccountKey.json")
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, options={
        'databaseURL': 'https://aspj-cddb3-default-rtdb.asia-southeast1.firebasedatabase.app/',
        # add a thing for cloud storage ~YX
        'storageBucket': 'gs://aspj-cddb3.appspot.com'
    })

import pyrebase

config = {
    "apiKey": os.getenv("FIREBASE_KEY"),
    "authDomain": "aspj-cddb3.firebaseapp.com",
    "databaseURL": "https://aspj-cddb3-default-rtdb.asia-southeast1.firebasedatabase.app",
    "storageBucket": "aspj-cddb3.appspot.com",
}

firebase = pyrebase.initialize_app(config)
db_ref = db.reference()
pyreauth = firebase.auth()

# initialize firestore
donation_db = firestore.client()

# initialize cloud storage
donation_cloud_storage = firebase.storage()

# initialize cloud storage bucket
donation_bucket = storage.bucket('aspj-cddb3.appspot.com')
