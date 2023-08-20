import io
import os
import re
import time
from typing import *

import requests
from better_profanity import profanity
from flask import flash, request, session
from flask_limiter.util import get_remote_address
from PIL import Image, ImageSequence

from firebaseconfig import donation_db
from GoogleCloudLogger import *
from dotenv import load_dotenv
load_dotenv()
# define a regex pattern to find special characters
special_char_pattern = re.compile(r'[@#^&*+=[\]{}|\\:;"\']')


def get_ip_address():
    try:
        ip = request.headers.get('X-Forwarded-For', get_remote_address())
        return ip
    except:
        return 'Unknown'

def donation_form_validate(donation_form: object) -> bool:

    donation_log_debug(get_ip_address(), session['id'], "Validating donation form...")

    try:
        # retrieve our list of filters
        donation_db_profanities_list = []
        donation_db_profanities_docs = donation_db.collection('profanities').stream()
        for donation_db_profanities_doc in donation_db_profanities_docs:
            # convert to dict
            donation_db_profanities_doc = donation_db_profanities_doc.to_dict()
            # check if enabled or not
            if donation_db_profanities_doc['enabled'] == True:
                # put new things into list
                donation_db_profanities_list.append(donation_db_profanities_doc['profanity'])

        donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

        # add our own list of words
        profanity.load_censor_words(donation_db_profanities_list)

        # donation amount minimum
        if float(donation_form['amount']) < 1:
            donation_log_warning(get_ip_address(), session['id'], "Donation form validation fail: donation_amount < 1")
            flash('Minimum donation amount is $1.00', 'warning')
            return False

        # donation amount maximum
        elif float(donation_form['amount']) > 200000:
            donation_log_warning(get_ip_address(), session['id'], "Donation form validation fail: donation_amount > 200000")
            flash('Maximum donation amount is $200,000.00', 'warning')
            return False

        # comment profanity detection
        elif profanity.contains_profanity(donation_form['comment']):
            donation_log_warning(get_ip_address(), session['id'], "Donation form validation fail: Profanity detected")
            flash('Profanity detected, please try again', 'warning')
            return False
        
        # check for special characters in comment
        elif special_char_pattern.search(donation_form['comment']):
            donation_log_warning(get_ip_address(), session['id'], "Donation form validation fail: Special characters detected")
            flash('Please avoid using special characters in the comment', 'warning')
            return False

        else:
            donation_log_info(get_ip_address(), session['id'], "Donation form validated")
            return True

    except:
        donation_log_critical(get_ip_address(), session['id'], "Donation form validation fail: Unknown error")
        flash('Unknown error occured', 'danger')
        return False


def donation_form_validate_users(donation_form: object, user_id: str) -> bool:

    donation_log_debug(get_ip_address(), session['id'], "Validating donation users form...")

    try:
        # donation points minimum
        if float(donation_form['points-' + user_id]) < 0:
            donation_log_warning(get_ip_address(), session['id'], "Donation users form validation fail: points < 0")
            flash('Minimum points is 0', 'warning')
            return False

        else:
            donation_log_info(get_ip_address(), session['id'], "Donation users form validated")
            return True

    except:
        donation_log_critical(get_ip_address(), session['id'], "Donation form validation fail: Unknown error")
        flash('Unknown error occured', 'danger')
        return False


def donation_form_validate_rewards(donation_form: object) -> bool:

    donation_log_debug(get_ip_address(), session['id'], "Validating donation rewards form...")

    try:

        donation_log_debug(get_ip_address(), session['id'], "Retrieving from profanities collection database...")

        # retrieve our list of filters
        donation_db_profanities_list = []
        donation_db_profanities_docs = donation_db.collection('profanities').stream()
        for donation_db_profanities_doc in donation_db_profanities_docs:
            # convert to dict
            donation_db_profanities_doc = donation_db_profanities_doc.to_dict()
            # put new things into list
            donation_db_profanities_list.append(donation_db_profanities_doc['profanity'])

        donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

        # add our own list of words
        profanity.load_censor_words(donation_db_profanities_list)

        # level minimum
        if int(donation_form) < 0:
            donation_log_warning(get_ip_address(), session['id'], "Donation rewards form validation fail: level < 0")
            flash('Minimum level is 0', 'warning')
            return False

        # name profanity detection
        elif profanity.contains_profanity(donation_form['name']):
            donation_log_warning(get_ip_address(), session['id'], "Donation rewards form validation fail: Profanities detected in name")
            flash('Profanity detected, please try again', 'warning')
            return False

        # description profanity detection
        elif profanity.contains_profanity(donation_form['description']):
            donation_log_warning(get_ip_address(), session['id'], "Donation rewards form validation fail: Profanities detected in description")
            flash('Profanity detected, please try again', 'warning')
            return False
        
        # check for special characters in description
        elif special_char_pattern.search(donation_form['description']):
            donation_log_warning(get_ip_address(), session['id'], "Donation form validation fail: Special characters detected")
            flash('Please avoid using special characters in the description', 'warning')
            return False
        
        else:
            donation_log_info(get_ip_address(), session['id'], "Donation rewards form validated")
            return True

    except:
        donation_log_critical(get_ip_address(), session['id'], "Donation rewards form validation fail: Unknown error occurred")
        flash('Unknown error occurred', 'danger')
        return False


def donation_profanity_validate(string: str) -> bool:

    donation_log_debug(get_ip_address(), session['id'], "Validating donation form profanities...")

    # retrieve list of filters

    donation_log_debug(get_ip_address(), session['id'], "Retrieving from profanities collection database...")

    donation_db_profanities_list = []
    donation_db_profanities_docs = donation_db.collection('profanities').stream()
    for donation_db_profanities_doc in donation_db_profanities_docs:
        # convert to dict
        donation_db_profanities_doc = donation_db_profanities_doc.to_dict()

        # check if enabled or not
        if donation_db_profanities_doc['enabled'] == True:
            # put new things into list
            donation_db_profanities_list.append(donation_db_profanities_doc['profanity'])

    donation_log_debug(get_ip_address(), session['id'], "Retrieve success")

    # add our own list of words
    profanity.load_censor_words(donation_db_profanities_list)

    if profanity.contains_profanity(string):
        donation_log_warning(get_ip_address(), session['id'], "Donation form profanities validation fail: Profanities detected")
        flash('Profanity detected, please try again', 'warning')
        return False
    else:
        donation_log_info(get_ip_address(), session['id'], "Donation form profanities validated")
        return True


def donation_file_check(file: object) -> bool:

    donation_log_debug(get_ip_address(), session['id'], "Checking uploaded files for virus...")

    donation_log_debug(get_ip_address(), session['id'], "Uploading file to VirusTotal...")
    # upload endpoint
    files_url = "https://www.virustotal.com/api/v3/files"

    # specify post payload
    files = {"file": (file.filename, file, file.content_type)}
    files_headers = {
        "accept": "application/json",
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")
    }

    # post
    donation_log_debug(get_ip_address(), session['id'], f"Posting payload [{files_url}, {files}, {files_headers}]...")
    files_response = requests.post(files_url, files=files, headers=files_headers)
    donation_log_debug(get_ip_address(), session['id'], f"files_response [{files_response}]")

    # get response
    if files_response.status_code == 200:
        # if response is ok
        files_response_data = files_response.json()
        donation_log_debug(get_ip_address(), session['id'], "Response ok")
        donation_log_debug(get_ip_address(), session['id'], f"Data received [{files_response_data}]")

        # get the id from json response
        analysis_id = files_response_data["data"]["id"]

    else:
        # handle errors
        flash('Unknown error occured', 'danger')
        return False

    # analysis endpoint with file id
    analysis_url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id

    # specify headers
    analysis_headers = {
        "accept": "application/json",
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")
    }

    # post
    donation_log_debug(get_ip_address(), session['id'], f"Posting payload [{analysis_url}, {analysis_headers}]")
    analysis_response = requests.get(analysis_url, headers=analysis_headers)
    donation_log_debug(get_ip_address(), session['id'], f"analysis_response [{analysis_response}]")

    # declare attempts count
    attempts = 1

    # retry getting analysis response for max 120 times in 2 minutes if virustotal slow like snorlax
    donation_log_debug(get_ip_address(), session['id'], "Waiting for analysis response...")
    while attempts < 120 and analysis_response.status_code == 200 and analysis_response.json()["data"]["attributes"]["status"] in ['queued', 'in-progress']:
        donation_log_debug(get_ip_address(), session['id'], f"Attempt: {attempts}")
        time.sleep(1)
        analysis_response = requests.get(analysis_url, headers=analysis_headers)
        donation_log_debug(get_ip_address(), session['id'], f"analaysis_response [{analysis_response.json()}]")
        attempts += 1

        # if attempts more than 30 just timeout
        if attempts >= 120:
            donation_log_critical(get_ip_address(), session['id'], "VirusTotal analysis response timeout")
            flash('File processing timeout', 'danger')
            return False

    # get response
    if analysis_response.status_code == 200:
        donation_log_debug(get_ip_address(), session['id'], "Response ok")
        # if response is ok
        analysis_response_data = analysis_response.json()
        donation_log_debug(get_ip_address(), session['id'], f"Data received [{analysis_response_data}]")
        # get number of engine that found the file sus
        amogusus = analysis_response_data["data"]["attributes"]["stats"]["suspicious"]
        malicious = analysis_response_data["data"]["attributes"]["stats"]["malicious"]

        # if got sussy
        if amogusus > 0 or malicious > 0:
            donation_log_critical(get_ip_address(), session['id'], "There do be an impostor file amongus")
            flash('Please upload another file', 'danger')
            return False

        # if no sussy
        elif amogusus == 0 and malicious == 0:
            # reset the file cursor to the start
            file.seek(0)
            donation_log_info(get_ip_address(), session['id'], "Virus check passed")
            return True

        else:
            donation_log_critical(get_ip_address(), session['id'], "Virus check fail: Unknown error occurred")
            flash('Unknown error occurred', 'danger')
            return False

    else:
        # handle errors
        donation_log_critical(get_ip_address(), session['id'], "Virus check fail: Unknown error occurred")
        flash('Unknown error occurred', 'danger')
        return False


def donation_image_check(image: object) -> bool:

    donation_log_debug(get_ip_address(), session['id'], "Checking for image filetype...")

    try:
        # check if extension is one of those after splitting using the .
        donation_log_debug(get_ip_address(), session['id'], "Checking filename extension...")
        if image and '.' in image.filename and image.filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'webp'}:
            donation_log_debug(get_ip_address(), session['id'], "Filename extension is valid")
            # check if file uploaded is image filetype
            try:
                # try to open image
                donation_log_debug(get_ip_address(), session['id'], "Checking if file is an image format...")
                Image.open(image.stream)

                # reset cursor
                image.seek(0)
                donation_log_info(get_ip_address(), session['id'], "Image filetype validation pass")
                return True

            except IOError:
                donation_log_warning(get_ip_address(), session['id'], "Image filetype validation fail: File is not an image")
                flash('Invalid file type, please select an image', 'warning')
                return False

            except:
                donation_log_critical(get_ip_address(), session['id'], "Image filetype validation fail: Unknown error occurred")
                flash('Unknown error occurred', 'danger')
                return False

        # if file uploaded is not with the correct extension
        else:
            donation_log_warning(get_ip_address(), session['id'], "Filename extension is invalid")
            flash('Invalid file type. Only png, jpg, jpeg, and webp are allowed.', 'warning')
            return False

    except:
        donation_log_critical(get_ip_address(), session['id'], "Image filetype validation fail: Unknown error occurred")
        flash('Unknown error occurred', 'danger')


def donation_image_reformat(image: object) -> object:
    
    donation_log_debug(get_ip_address(), session['id'], "Reformatting image...")
    
    # get the image itself
    donation_log_debug(get_ip_address(), session['id'], "Opening image file...")
    img = Image.open(image.stream)

    # check if image is animated
    donation_log_debug(get_ip_address(), session['id'], "Checking if image is animated...")
    if getattr(img, 'is_animated', False) == True:
        donation_log_debug(get_ip_address(), session['id'], "Image is animated")
        # if image is animated
        img_frames = []
        # if any side of image is less than 1024 pixels, warn
        donation_log_debug(get_ip_address(), session['id'], "Checking for low resolution")
        if img.size[0] < 1024 or img.size[1] < 1024:
            donation_log_debug(get_ip_address(), session['id'], "Low resolution detected")
            donation_log_debug(get_ip_address(), session['id'], "Resizing each frame...")
            frameNo = 1
            for frame in ImageSequence.Iterator(img):
                donation_log_debug(get_ip_address(), session['id'], f"Resizing frame {frameNo}")
                frameNo += 1
                # resize image to longest side
                if frame.size[0] > frame.size[1]:
                    frame = frame.resize((frame.size[0], frame.size[0]), Image.ANTIALIAS)
                elif frame.size[1] > frame.size[0]:
                    frame = frame.resize((frame.size[1], frame.size[1]), Image.ANTIALIAS)
                else:
                    frame = frame.resize((1024, 1024), Image.ANTIALIAS)

                # add each frame to list
                img_frames.append(frame)

                donation_log_debug(get_ip_address(), session['id'], f"Resizing frame {frameNo} success")

            flash('Low quality animation selected, image has been resized', 'warning')

        else:
            frameNo = 1
            for frame in ImageSequence.Iterator(img):
                donation_log_debug(get_ip_address(), session['id'], f"Resizing frame {frameNo}")
                frameNo += 1
                # resize all images to 1024 pixels
                frame = frame.resize((1024, 1024), Image.ANTIALIAS)

                # add each frame to list
                img_frames.append(frame)

                donation_log_debug(get_ip_address(), session['id'], f"Resizing frame {frameNo} success")

        # save new image to stream
        image_io = io.BytesIO()

        # format image to webp
        img_frames[0].save(image_io, 'WEBP', save_all=True, append_images=img_frames[1:], loop=0)
        image_io.seek(0)
        donation_log_debug(get_ip_address(), session['id'], "Image formatted to WebP")

        return image_io

    else:
        donation_log_debug(get_ip_address(), session['id'], "Image is not animated")
        # if image is not animiated
        # if any side of image is less than 1024 pixels, warn
        donation_log_debug(get_ip_address(), session['id'], "Checking for low resolution")
        if img.size[0] < 1024 or img.size[1] < 1024:
            donation_log_debug(get_ip_address(), session['id'], "Low resolution detected")
            donation_log_debug(get_ip_address(), session['id'], "Resizing image...")
            # resize image to longest side
            if img.size[0] > img.size[1]:
                img = img.resize((img.size[0], img.size[0]), Image.ANTIALIAS)
            elif img.size[1] > img.size[1]:
                img = img.resize((img.size[1], img.size[1]), Image.ANTIALIAS)
            else:
                img = img.resize((1024, 1024), Image.ANTIALIAS)

            donation_log_debug(get_ip_address(), session['id'], f"Resizing image success")

            flash('Low quality image selected, image has been resized', 'warning')

        else:
            # resize all images to 1024 pixels
            donation_log_debug(get_ip_address(), session['id'], "Resizing image...")
            img = img.resize((1024, 1024), Image.ANTIALIAS)
            donation_log_debug(get_ip_address(), session['id'], f"Resizing image success")

        # save new image to stream
        image_io = io.BytesIO()

        # format image to webp
        img.save(image_io, 'WEBP')
        image_io.seek(0)
        donation_log_debug(get_ip_address(), session['id'], "Image formatted to WebP")

        return image_io


# duplicate
def mission_image_reformat(image: object) -> object:
    # get the image itself
    img = Image.open(image.stream)
    # if any side of image is less than 1024 pixels, warn

    if img.size[0] < 1024 or img.size[1] < 1024:
        # resize image to longest side
        if img.size[0] > img.size[1]:
            img = img.resize((img.size[0], img.size[0]), Image.ANTIALIAS)
        elif img.size[1] > img.size[1]:
            img = img.resize((img.size[1], img.size[1]), Image.ANTIALIAS)
        else:
            img = img.resize((1024, 1024), Image.ANTIALIAS)

        flash('Low quality image selected, image has been resized', 'warning')

    else:
        # resize all images to 1024 pixels
        img = img.resize((1024, 1024), Image.ANTIALIAS)

    # save new image to stream
    image_io = io.BytesIO()

    # format image to webp
    img.save(image_io, 'WEBP')
    image_io.seek(0)

    return image_io
