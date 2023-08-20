from DBRetrieve import update_user_attribute_unencrypted, get_user_attribute_unencrypted, get_user_attribute_encrypted, update_user_attribute_encrypted, get_user_id, update_user_attribute_id, set_password
from firebaseconfig import db_ref
from sexyencryption import encrypt, decrypt
from DBRetrieve import lock, unlock, delete_user
from sessions import*
from datetime import datetime, timedelta
from GoogleAuthenticator2FA import *


def encryptall():
    users_ref = db_ref.child("users")
    query_result = users_ref.get()

    for user_id, user_data in query_result.items():
        # Encrypt specific attributes
        user_data['first_name'] = encrypt(user_data['first_name'])
        user_data['last_name'] = encrypt(user_data['last_name'])
        user_data['username'] = encrypt(user_data['username'])
        user_data['email'] = encrypt(user_data['email'])
        user_data['phone_num'] = encrypt(user_data['phone_num'])
        try:
            user_data['postal_code'] = encrypt(user_data['postal_code'])
        except:
            pass
        try:
            user_data['address'] = encrypt(user_data['address'])
        except:
            pass
        try:
            user_data['lower_address'] = encrypt(user_data['lower_address'])
        except:
            pass
        try:
            user_data['lower_email'] = encrypt(user_data['lower_email'])
        except:
            pass
        try:
            user_data['lower_username'] = encrypt(user_data['lower_username'])
        except:
            pass

        # Update the encrypted data in the database
        users_ref.child(user_id).update(user_data)
    return

def decryptall():
    users_ref = db_ref.child("users")
    query_result = users_ref.get()
    for user_id, user_data in query_result.items():
        # Decrypt specific attributes
        print(user_data['first_name'])
        user_data['first_name'] = decrypt(user_data['first_name'])
        user_data['last_name'] = decrypt(user_data['last_name'])
        user_data['username'] = decrypt(user_data['username'])
        user_data['email'] = decrypt(user_data['email'])
        user_data['phone_num'] = decrypt(user_data['phone_num'])
        try:
            user_data['postal_code'] = decrypt(user_data['postal_code'])
        except:
            pass
        try:
            user_data['address'] = decrypt(user_data['address'])
        except:
            pass
        try:
            user_data['lower_address'] = decrypt(user_data['lower_address'])
        except:
            pass
        try:
            user_data['lower_email'] = decrypt(user_data['lower_email'])
        except:
            pass
        try:
            user_data['lower_username'] = decrypt(user_data['lower_username'])
        except:
            pass

        # Update the decrypted data in the database
        users_ref.child(user_id).update(user_data)
    return


def updateall(attribute, value):
    users_ref = db_ref.child("users")
    query_result = users_ref.get()
    for user_id, user_data in query_result.items():
        print(user_id)
        users_ref.child(user_id).update({attribute: value})
    return

