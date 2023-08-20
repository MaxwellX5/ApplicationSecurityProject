from firebaseconfig import db_ref, pyreauth, auth, donation_cloud_storage, donation_db, donation_bucket
import os
from flask import flash, redirect, request, session
from typing import *
from firebase_admin.auth import UserRecord
from sexyencryption import encrypt, decrypt
def get_user_id(id, attribute):
    users_ref = db_ref.child("users")
    query_result = users_ref.order_by_child('id').equal_to(id).get()

    for user_id, user_data in query_result.items():
        attribute_value = user_data.get(attribute)
        if attribute_value is not None:
            return attribute_value

    return None
def update_user_attribute_id(id, attribute, new_value):
    users_ref = db_ref.child("users")
    query_result = users_ref.order_by_child('id').equal_to(id).get()
    for user_id, user_data in query_result.items():
        user_data[attribute] = (new_value)
        users_ref.child(user_id).set(user_data)

    return None

def get_user_attribute_encrypted(session_id, attribute):
    session_ref = db_ref.child("sessions")
    query_result = session_ref.order_by_child('session_id').equal_to(session_id).get()
    for session_id, session_data in query_result.items():
        user_id = session_data.get('id')
        if user_id is not None:
            users_ref = db_ref.child("users")
            query_result = users_ref.order_by_child('id').equal_to(user_id).get()
            for user_id, user_data in query_result.items():
                attribute_value = user_data.get(attribute)
                if attribute_value is not None:
                    return decrypt(attribute_value)

    return None

def update_user_attribute_encrypted(session_id, attribute, new_value):
    session_ref = db_ref.child("sessions")
    query_result = session_ref.order_by_child('session_id').equal_to(session_id).get()
    for session_id, session_data in query_result.items():
        user_id = session_data.get('id')
        if user_id is not None:
            users_ref = db_ref.child("users")
            query_result = users_ref.order_by_child('id').equal_to(user_id).get()
            for user_id, user_data in query_result.items():
                user_data[attribute] = encrypt(new_value)
                users_ref.child(user_id).set(user_data)

    return None

def get_user_attribute_unencrypted(session_id, attribute):
    session_ref = db_ref.child("sessions")
    query_result = session_ref.order_by_child('session_id').equal_to(session_id).get()
    for session_id, session_data in query_result.items():
        user_id = session_data.get('id')
        if user_id is not None:
            users_ref = db_ref.child("users")
            query_result = users_ref.order_by_child('id').equal_to(user_id).get()
            for user_id, user_data in query_result.items():
                attribute_value = user_data.get(attribute)
                if attribute_value is not None:
                    return attribute_value

    return None

def update_user_attribute_unencrypted(session_id, attribute, new_value):
    session_ref = db_ref.child("sessions")
    query_result = session_ref.order_by_child('session_id').equal_to(session_id).get()
    for session_id, session_data in query_result.items():
        user_id = session_data.get('id')
        if user_id is not None:
            users_ref = db_ref.child("users")
            query_result = users_ref.order_by_child('id').equal_to(user_id).get()
            for user_id, user_data in query_result.items():
                user_data[attribute] = (new_value)
                users_ref.child(user_id).set(user_data)

    return None

def delete_user(email):
    users_ref = db_ref.child("users")
    query_result = users_ref.get()
    uid_to_delete = None

    for user_id, user_data in query_result.items():
        user_email = decrypt(user_data.get('email'))
        if user_email == email:
            uid = user_data.get('id')
            uid_to_delete = uid
            realtimeid = user_id
            break
    if uid_to_delete:
        try:
            # Delete user from Firebase Authentication
            auth.delete_user(uid_to_delete)
            users_ref.child(realtimeid).delete()
        except Exception as e:
            print("Error deleting user:", str(e))
    else:
        print("User with email", email, "not found.")
def lock(email):
    users_ref = db_ref.child("users")
    query_result = users_ref.get()
    uid_to_disable = None

    for user_id, user_data in query_result.items():
        user_email = decrypt(user_data.get('email'))
        if user_email == email:
            uid = user_data.get('id')
            uid_to_disable = uid
            break

    if uid_to_disable:
        try:
            # Delete user from Firebase Authentication
            auth.update_user(uid_to_disable, disabled=True)
            update_user_attribute_id(uid, 'lock', True)
        except Exception as e:
            print("Error locking user:", str(e))
    else:
        print("User with email", email, "not found.")

def unlock(email):
    users_ref = db_ref.child("users")
    query_result = users_ref.get()
    uid_to_enable = None

    for user_id, user_data in query_result.items():
        user_email = decrypt(user_data.get('email'))
        if user_email == email:
            uid = user_data.get('id')
            uid_to_enable = uid
            break
    if uid_to_enable:
        try:
            auth.update_user(uid_to_enable, disabled=False)
            update_user_attribute_id(uid, 'lock', False)
        except Exception as e:
            print("Error unlocking user:", str(e))
    else:
        print("User with email", email, "not found.")

import base64

def get_profile_picture_url(session_id):
    pfp = get_user_attribute_unencrypted(session_id, 'pfp')
    if pfp:
        try:
            pfp = base64.b64decode(pfp)
            profile_picture_url = "data:image/png;base64," + base64.b64encode(pfp).decode('utf-8')
            return profile_picture_url
        except:
            print("Error decoding picture")
    return "https://www.pngitem.com/pimgs/m/146-1468479_my-profile-icon-blank-profile-picture-circle-hd.png"


# retrieve from firestore, pass in the collection name
def firestore_read_collection(collection: str) -> list[object]:
    # declare list
    donation_db_list = []
    # retrieve data
    donation_db_docs = donation_db.collection(collection).stream()
    # iterate through things
    for donation_db_doc in donation_db_docs:
        # convert to dict
        donation_db_doc = donation_db_doc.to_dict()
        # put new things into list
        donation_db_list.append(donation_db_doc)
    return donation_db_list


# pass an image file straight from the form, e.g: image = request.files['your-image-form-field']
def validate_image(image: object) -> bool:
    # extract filename from object
    image_name = image.filename
    # check if extension is one of those after splitting using the .
    if image and '.' in image_name and image_name.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'webp'}:
        # return true when validate pass
        return True

    else:
        # return false when validate fails
        return False


# pass an image file straight from the form, e.g: image = request.files['your-image-form-field']
def cloud_storage_set_image(image: object, image_path: str) -> Tuple[str, str]:

    # split file name and file extension
    image_name, image_ext = os.path.splitext(image.filename)

    # set image path
    image_path = str(image_path) + image_ext

    # upload the goods
    donation_cloud_storage.child(image_path).put(image)

    # get url of uploaded file
    image_url = donation_cloud_storage.child(image_path).get_url(None)

    # return image_url and image_path
    return image_url, image_path

def cloud_storage_set_face_image(image: object, image_path: str) -> Tuple[str, str]:
    # split file name and file extension
    image_ext = "jpg"

    # set image path
    image_path = str(image_path) + image_ext

    # upload the goods
    donation_cloud_storage.child(image_path).put(image)

    # get url of uploaded file
    image_url = donation_cloud_storage.child(image_path).get_url(None)

    # return image_url and image_path
    return image_url, image_path

def cloud_storage_set_image_mission(image: object, image_path: str) -> Tuple[str, str]:

    # set image path
    image_path = str(image_path) + ".webp"

    # upload the goods
    donation_cloud_storage.child(image_path).put(image)

    # get url of uploaded file
    image_url = donation_cloud_storage.child(image_path).get_url(None)

    # return image_url and image_path
    return image_url, image_path

# delete image
def cloud_storage_delete_image(image_path: str) -> None:
    blob = donation_bucket.blob(image_path)
    blob.delete()
    return None


# get profile picture, even for initial user
def cloud_storage_get_profile_image_url(user_id: str) -> str:

    # get image_url of the specified user
    image_url = get_user_id(user_id, 'image_url')

    # check if user is new without profile pic
    if image_url == '':
        # if user is new, then image_url will be blank string
        return "static/img/accounts/default-profile.svg"

    else:
        # if user is not new
        return image_url



def cloud_storage_get_profile_image_url_sess(user_id: str) -> str:

    # get image_url of the specified user
    image_url = get_user_attribute_unencrypted(user_id, 'image_url')

    # check if user is new without profile pic
    if image_url == '':
        # if user is new, then image_url will be blank string
        return "static/img/accounts/default-profile.svg"

    else:
        # if user is not new
        return image_url

def set_email(user_id: str, email: str) -> UserRecord:
    return auth.update_user(user_id, email=email)

def set_password(user_id: str, password: str) -> UserRecord:
    return auth.update_user(user_id, password=password)

def set_email_verified(user_id: str, email_verified: bool) -> UserRecord:
    return auth.update_user(user_id, email_verified=email_verified)
