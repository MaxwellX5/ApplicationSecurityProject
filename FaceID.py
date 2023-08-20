import requests
import cv2
import time
import mimetypes
from DBRetrieve import update_user_attribute_unencrypted, get_user_attribute_unencrypted, cloud_storage_delete_image, cloud_storage_set_face_image, get_user_id
from flask import session
import os
from io import BytesIO
from firebaseconfig import db_ref
from dotenv import load_dotenv
FACEID_APIKEY = os.getenv("FACE_API_KEY")
FACEID_APISECRET = os.getenv("FACE_API_SECRET")
COMPARE_URL = 'https://api-us.faceplusplus.com/facepp/v3/compare'
DETECT_URL = 'https://api-us.faceplusplus.com/facepp/v3/detect'
load_dotenv()

def register_face(image):
    data = {
        'api_key': FACEID_APIKEY,
        'api_secret': FACEID_APISECRET,
    }
    # Prepare the image file for upload
    files = {
        'image_file': (image, open(image, 'rb'), 'application/octet-stream')
    }

    # Send the request
    response = requests.post(DETECT_URL, data=data, files=files)

    # Process the response
    result = response.json()
    # os.remove(image)
    # Print the result
    if 'faces' in result:
        face_token = result['faces'][0]['face_token']
        print("Face detected")
        print(f"Face token: {face_token}")
        if get_user_attribute_unencrypted(session['id'],'face') != None:
            cloud_storage_delete_image(get_user_attribute_unencrypted(session['id'],'face_path'))
        image_url, image_path = cloud_storage_set_face_image(
        image, 'face/' + get_user_attribute_unencrypted(session['id'],'id'))
        update_user_attribute_unencrypted(session['id'], 'face_url', image_url)
        update_user_attribute_unencrypted(session['id'], 'face_path', image_path)
        return True
    else:
        print("Error:", result.get('error_message', 'Unknown error'))
        return False

def verify_face(user_id,image2):
    face_url = get_user_id(user_id, 'face_url')
    if face_url != None:
        data = {
            'api_key': FACEID_APIKEY,
            'api_secret': FACEID_APISECRET,
            'image_url1': face_url
        }
        # Send the request
        files = {
            'image_file2': (image2, open(image2, 'rb'), 'application/octet-stream')
        }
        response = requests.post(COMPARE_URL, data=data, files=files)
        # os.remove(image2)
        # Process the response
        result = response.json()

        # Print the result
        if 'confidence' in result:
            confidence = result['confidence']
            if confidence > 80:
                print(f"Faces are from the same person (Confidence: {confidence}%)")
                return True
            else:
                print("Faces are not from the same person")
                print(f"Confidence: {confidence}%")
                return False
        else:
            print("Error:", result.get('error_message', 'Unknown error'))
            return False
    return None

def capture_face():
    cap = cv2.VideoCapture(0)
    while True:
        ret, frame = cap.read()
        frame = cv2.putText(cv2.flip(frame, 1), "Press 'q' to quit or 'Space' to Capture!", (0, 25), cv2.FONT_HERSHEY_SIMPLEX, 1,
                            (0, 0, 255), 4)
        if not ret:
            print("failed to grab frame")
            break
        cv2.imshow('frame', frame)
        key = cv2.waitKey(1) & 0xFF
        if key == ord('q'):
            return "quit"
        elif key == ord(' '):
            cv2.imwrite('faceimage.jpg', frame)
            break
    cap.release()
    cv2.destroyAllWindows()
    return

def detect_face(image):
    allowed_extensions = {'png', 'jpg', 'jpeg'}
    def is_allowed_image_file(file):
        mimetype = mimetypes.guess_type(file.filename)[0]
        return mimetype is not None and mimetype.startswith('image') and mimetype.split('/')[1] in allowed_extensions

    if is_allowed_image_file:
        data = {
            'api_key': FACEID_APIKEY,
            'api_secret': FACEID_APISECRET,
        }
        files = {
            'image_file': (image, open(image, 'rb'), 'application/octet-stream')
        }
        response = requests.post(DETECT_URL, data=data, files=files)
        result = response.json()
        if 'faces' in result:
            return True
        else:
            return False
    else:
        print("Invalid file")
        return False
