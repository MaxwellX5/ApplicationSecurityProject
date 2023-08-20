from datetime import datetime, timedelta
from firebaseconfig import db_ref
from DBRetrieve import get_user_attribute_unencrypted, update_user_attribute_unencrypted, get_user_id, update_user_attribute_id
MAX_TIME = timedelta(hours=1)
import secrets

def generate_session_id(user_id):
    generated_session_id = secrets.token_urlsafe(32)  # Generate a random session ID
    sessions_ref = db_ref.child("sessions")
    query_result = sessions_ref.order_by_child('session_id').equal_to(generated_session_id).get()
    if len(query_result) != 0:
        """ If the session ID already exists, generate a new one """
        return generate_session_id(user_id)

    else:
        query_result = sessions_ref.order_by_child('id').equal_to(user_id).get()
        for session_id, session_data in query_result.items():
            sessions_ref.child(session_id).delete()
        time = datetime.now()
        if isinstance(time, datetime):
            time = time.isoformat()
        new_session = {"session_id": generated_session_id, "id": user_id, "last_active": time}
        new_session_ref = db_ref.child('sessions').push(new_session)
        return generated_session_id

def expiry_check(session_id):
    #Checks if any sessions have expired and removes them from the database
    sessions_ref = db_ref.child("sessions")
    query_result = sessions_ref.order_by_child('session_id').equal_to(session_id).get()
    for session_id, session_data in query_result.items():
        last_active = session_data.get('last_active')
        if isinstance(last_active, str):
            last_active = datetime.fromisoformat(last_active)
        if datetime.now() - last_active >= MAX_TIME:
            sessions_ref.child(session_id).delete()
            print("Session expired")
            return True
    return False

