# --- UPDATED auth.py ---

import streamlit as st
import hashlib
from db import users_collection

# --- Utility ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def signup_user(first_name, last_name, email, password):
    if users_collection.find_one({"email": email}):
        return False, "Email already registered."

    user_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": hash_password(password),
    }
    users_collection.insert_one(user_data)
    return True, "Account created successfully."

def authenticate_user(email, password):
    user = users_collection.find_one({"email": email})
    if user and user.get("password") == hash_password(password):
        return True, user
    return False, None

# --- Login / Signup UI ---
def login_signup_page():
    st.markdown("""
        <style>
            .auth-box {
                background-color: #f5f7fa;
                padding: 2.5rem;
                border-radius: 16px;
                max-width: 450px;
                margin: 3rem auto;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            }
            .auth-title {
                font-size: 28px;
                text-align: center;
                font-weight: 700;
                margin-bottom: 1.5rem;
            }
            .auth-button {
                background-color: #2c7be5;
                color: white;
                border: none;
                width: 100%;
                padding: 0.7rem;
                font-size: 16px;
                border-radius: 8px;
                cursor: pointer;
                transition: 0.3s ease-in-out;
            }
            .auth-button:hover {
                background-color: #1a5fc2;
            }
            .google-btn {
                background-color: #fff;
                color: #444;
                border: 1px solid #ccc;
                font-weight: 500;
            }
            .google-btn:hover {
                background-color: #f1f1f1;
            }
            .link-text {
                font-size: 0.9rem;
                text-align: center;
                margin-top: 1rem;
            }
            .form-field {
                margin-bottom: 1rem;
            }
        </style>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔐 Login", "🆕 Signup"])

    # --- LOGIN ---
    with tab1:
        st.markdown('<div class="auth-box">', unsafe_allow_html=True)
        st.markdown('<div class="auth-title">Welcome Back</div>', unsafe_allow_html=True)
        with st.form("login_form"):
            email = st.text_input("Email", placeholder="you@example.com", key="login_email")
            password = st.text_input("Password", type="password", placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022", key="login_pass")
            st.markdown('<div style="text-align:right"><a href="#">Forgot password?</a></div>', unsafe_allow_html=True)
            login_btn = st.form_submit_button("Login")

        if login_btn:
            success, user_data = authenticate_user(email, password)
            if success:
                st.success("Login successful.")
                st.session_state.authenticated = True
                st.session_state.user = email
                st.session_state.scan_id = user_data.get("_id", "N/A")  # unique user ID for linking
            else:
                st.error("Invalid email or password.")

        st.markdown('<p class="link-text">Don\'t have an account? Switch to Signup tab.</p>', unsafe_allow_html=True)
        st.divider()
        st.button("Login with Google", use_container_width=True, key="login_google", help="Google login placeholder", type="secondary")
        st.markdown('</div>', unsafe_allow_html=True)

    # --- SIGNUP ---
    with tab2:
        st.markdown('<div class="auth-box">', unsafe_allow_html=True)
        st.markdown('<div class="auth-title">Create an Account</div>', unsafe_allow_html=True)
        with st.form("signup_form"):
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name", placeholder="Jane", key="signup_fname")
            with col2:
                last_name = st.text_input("Last Name", placeholder="Doe", key="signup_lname")
            email = st.text_input("Email", placeholder="you@example.com", key="signup_email")
            password = st.text_input("Password", type="password", placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022", key="signup_pass")
            confirm = st.text_input("Confirm Password", type="password", placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022", key="signup_confirm")
            submit = st.form_submit_button("Signup")

        if submit:
            if not all([first_name, last_name, email, password, confirm]):
                st.error("Please fill out all fields.")
            elif password != confirm:
                st.error("Passwords do not match.")
            else:
                success, msg = signup_user(first_name, last_name, email, password)
                if success:
                    st.success(msg)
                    st.session_state.authenticated = True
                    st.session_state.user = email
                    _, user_data = authenticate_user(email, password)
                    st.session_state.scan_id = user_data.get("_id", "N/A")
                else:
                    st.error(msg)

        st.markdown('<p class="link-text">Already have an account? Switch to Login tab.</p>', unsafe_allow_html=True)
        st.divider()
        st.button("Signup with Google", use_container_width=True, key="signup_google", help="Google signup placeholder", type="secondary")
        st.markdown('</div>', unsafe_allow_html=True)
