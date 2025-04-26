import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Encryption key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Store data and failed attempts
stored_data = {} 
failed_attempts = 0

# Functions for password hashing and encryption/decryption
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    if encrypted_text in stored_data:
        if stored_data[encrypted_text]["passkey"] == hashed_passkey:
            failed_attempts = 0
            decrypted_bytes = cipher.decrypt(encrypted_text.encode())
            return decrypted_bytes.decode()
    failed_attempts += 1
    return None

# Set page configuration
st.set_page_config(page_title="🔒 Secure Data Encryption System", page_icon="🔐", layout="centered")

# Custom CSS for a better look
st.markdown(
    """
    <style>
        .stTextArea>div>div>textarea {
            background-color: #f0f4f8;
            border-radius: 8px;
            padding: 12px;
            font-size: 14px;
            font-family: 'Arial', sans-serif;
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 16px;
            border: none;
        }
        .stButton>button:hover {
            background-color: #45a049;
        }
        .stSidebar {
            background-color: #343a40;
        }
        .stSidebar .sidebar-content {
            color: white;
        }
        .stTitle {
            color: #2e6c8d;
        }
        .stMarkdown {
            font-size: 16px;
            color: #555;
        }
        .stSuccess, .stError {
            font-size: 14px;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            font-size: 12px;
            color: #888;
            margin-top: 40px;
        }
    </style>
    """, unsafe_allow_html=True
)

# Application Title
st.title("🔒 Secure Data Encryption System")
st.write("Welcome to the **Secure Data Encryption** app. Store and retrieve your data safely with an encryption passkey.")

# Sidebar menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Section
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This application allows you to securely store and retrieve data using your own passkey. Keep your data safe and encrypted.")

# Store Data Section
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter the text to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_pass}
            st.success(f"✅ Data encrypted and saved! Encrypted text:\n\n{encrypted_text}")
        else:
            st.error("⚠️ Please fill in both fields!")

# Retrieve Data Section
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Enter your encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success(f"✅ Decrypted Data:\n\n{result}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many wrong attempts! Please re-login.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

# Login Section
elif choice == "Login":
    st.subheader("🔑 Re-login Required")
    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":  # Correct Master Password
            failed_attempts = 0
            st.success("✅ Login successful! Please go back to Retrieve Data.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect Master Password!")

# Footer Section
st.markdown(
    '<div class="footer">This was created by Fatima.</div>',
    unsafe_allow_html=True
)
