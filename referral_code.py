from cryptography.fernet import Fernet

def encrypt_referral_code(code, encryption_key):
    fernet = Fernet(encryption_key)
    encrypted_code = fernet.encrypt(code.encode())
    return encrypted_code

def decrypt_referral_code(encrypted_code, decryption_key):
    fernet = Fernet(decryption_key)
    decrypted_code = fernet.decrypt(encrypted_code).decode()
    return decrypted_code


