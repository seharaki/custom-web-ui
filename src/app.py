from datetime import datetime, timedelta, timezone

import jwt
import jwt.algorithms
import streamlit as st  # all streamlit commands will be available through the "st" alias
import utils
from streamlit_feedback import streamlit_feedback
import threading
import time

UTC = timezone.utc

# Title
title = "X"

# Page Styling Configuration
st.set_page_config(page_title=title, layout="wide")

st.title(title)

# Hide Streamlit ... Menu
hide_streamlit_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        </style>
        """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# Safety Messaging
safety_message = 'X'

# Show Session Time
session_toggle = False

# Auto Clear Session Feature
auto_clear_session = True
idle_timeout_seconds = 30

# Init configuration
config_agent = utils.retrieve_config_from_agent()
if "aws_credentials" not in st.session_state:
    st.session_state.aws_credentials = None

# Initialize session state variables
if "messages" not in st.session_state:
    st.session_state.messages = []
if "clicked_samples" not in st.session_state:
    st.session_state.clicked_samples = []
if "conversationId" not in st.session_state:
    st.session_state.conversationId = ""
if "parentMessageId" not in st.session_state:
    st.session_state.parentMessageId = ""
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "questions" not in st.session_state:
    st.session_state.questions = []
if "answers" not in st.session_state:
    st.session_state.answers = []
if "input" not in st.session_state:
    st.session_state.input = ""
if "user_prompt" not in st.session_state:
    st.session_state.user_prompt = ""
if "show_feedback" not in st.session_state:
    st.session_state.show_feedback = False
if "show_feedback_success" not in st.session_state:
    st.session_state.show_feedback_success = False
if "response_processing" not in st.session_state:
    st.session_state.response_processing = False
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "warning_message" not in st.session_state:
    st.session_state.warning_message = False
if "last_interaction_time" not in st.session_state:
    st.session_state.last_interaction_time = datetime.now(tz=UTC)

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""
    st.session_state.last_interaction_time = datetime.now(tz=UTC)
    st.warning("Clearing chat")

def get_remaining_session_time():
    if "idc_jwt_token" in st.session_state and "expires_at" in st.session_state["idc_jwt_token"]:
        expires_at = st.session_state["idc_jwt_token"]["expires_at"]
        remaining_time = expires_at - datetime.now(tz=UTC)
        return remaining_time
    return None

def refresh_token_if_needed():
    if "idc_jwt_token" in st.session_state:
        remaining_time = get_remaining_session_time()
        if remaining_time and remaining_time < timedelta(minutes=5):
            try:
                token = oauth2.refresh_token(st.session_state.token, force=True)
                # Store refresh token if available
                if "refresh_token" in token:
                    st.session_state.refresh_token = token["refresh_token"]
                else:
                    token["refresh_token"] = st.session_state.refresh_token
                # Retrieve the Identity Center token
                st.session_state.token = token
                st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"], config_agent)
                st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
            except Exception as e:
                st.error(f"Error refreshing token: {e}. Refresh the page.")
                del st.session_state["token"]
                if "refresh_token" in st.session_state:
                    del st.session_state["refresh_token"]
                st.rerun()

def encode_urls_in_references(references):
    parts = references.split("URL: ")
    encoded_references = parts[0]
    for part in parts[1:]:
        end_pos = part.find("\n")
        if end_pos == -1:
            end_pos = len(part)
        url = part[:end_pos]
        rest = part[end_pos:]
        encoded_url = url.replace(' ', '%20')
        encoded_references += "URL: " + encoded_url + rest
    return encoded_references

def check_idle_time():
    st.warning("Calling check idle time")
    while True:
        if auto_clear_session:
            current_time = datetime.now(tz=UTC)
            idle_time = (current_time - st.session_state.last_interaction_time).total_seconds()
            st.warning(f"Calling check idle time {idle_time}")
            if idle_time > idle_timeout_seconds:
                clear_chat_history()
                st.rerun()
            st.session_state.idle_time_left = max(0, idle_timeout_seconds - idle_time)
        time.sleep(1)

oauth2 = utils.configure_oauth_component(config_agent.OAUTH_CONFIG)
if "token" not in st.session_state:
    redirect_uri = f"https://{config_agent.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    result = oauth2.authorize_button("Start Chatting", scope="openid email offline_access", pkce="S256", redirect_uri=redirect_uri)
    if result and "token" in result:
        # If authorization successful, save token in session state
        st.session_state.token = result.get("token")
        # Store refresh token if available
        if "refresh_token" in result["token"]:
            st.session_state.refresh_token = result["token"]["refresh_token"]
        else:
            st.error("No refresh token received.")
        # Retrieve the Identity Center token
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"], config=config_agent)
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + \
            timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        st.session_state.authenticated = True
        st.session_state.last_interaction_time = datetime.now(tz=UTC)
        st.rerun()
else:
    token = st.session_state["token"]
    refresh_token = token.get("refresh_token")  # saving the long lived refresh_token
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]
    if not refresh_token:
        st.error("No refresh token available. Please log in again.")
        del st.session_state["token"]
        st.rerun()

    # Automatic token refresh
    refresh_token_if_needed()

    col1, col2 = st.columns([1, 3])

    with col1:
        st.write("Logged in with DeviceID: ", user_email)

    if "messages" not in st.session_state or not st.session_state.messages:
        st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]

    # Display remaining session time
    remaining_time = get_remaining_session_time()
    if remaining_time:
        if session_toggle:
            st.info(f"Session expires in: {remaining_time}")

    # Define sample questions
    sample_questions = [
        "What is the cool thing about A",
        "What is the cool thing about B",
        "What is the cool thing about C",
        "What is the cool thing about D",
        "What is the cool thing about E"
    ]

    # Display sample question buttons
    st.markdown(
        """
        <style>
        .faq-title {
            text-align: center;
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 20px; /* Adjust the value as needed */
        }
        </style>
        <div class="faq-title">Frequently Asked Questions</div>
        """,
        unsafe_allow_html=True
    )
    cols = st.columns(len(sample_questions))
    for idx, question in enumerate(sample_questions):
        cols[idx].button(
            question,
            key=question,
            disabled=st.session_state.response_processing,
            help="Click to ask",
            on_click=lambda q=question: ask_question(q)
        )

def ask_question(question):
    st.session_state.clicked_samples.append(question)
    st.session_state.user_prompt = question
    st.session_state.messages.append({"role": "user", "content": question})
    st.session_state.response_processing = True
    st.session_state.last_interaction_time = datetime.now(tz=UTC)

# Add a horizontal line after the sample questions
st.markdown("<hr>", unsafe_allow_html=True)

# Display the chat messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

# User-provided prompt
if prompt := st.chat_input(key="chat_input"):
    st.session_state.user_prompt = prompt
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.write(prompt)
    st.session_state["show_feedback"] = False
    st.session_state.response_processing = True
    st.session_state.last_interaction_time = datetime.now(tz=UTC)

if st.session_state.messages and st.session_state.messages[-1]["role"] == "user":
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            placeholder = st.empty()
            response = utils.get_queue_chain(
                st.session_state.user_prompt,
                st.session_state["conversationId"],
                st.session_state["parentMessageId"],
                st.session_state["idc_jwt_token"]["idToken"],
                config_agent
            )
            if "references" in response:
                full_response = f"""{response["answer"]}\n\n---\n{encode_urls_in_references(response["references"])}"""
            else:
                full_response = f"""{response["answer"]}\n\n---\nNo sources"""
            placeholder.markdown(full_response)
            st.session_state["conversationId"] = response["conversationId"]
            st.session_state["parentMessageId"] = response["parentMessageId"]

        st.session_state.messages.append({"role": "assistant", "content": full_response})
        utils.store_message_response(
            user_email=user_email,
            conversation_id=st.session_state["conversationId"],
            parent_message_id=st.session_state["parentMessageId"],
            user_message=st.session_state.user_prompt,
            response=response,
            config=config_agent
        )
        st.session_state["show_feedback"] = True
        st.session_state["show_feedback_success"] = False
        st.session_state.response_processing = False
        st.session_state.warning_message = True
        st.warning(safety_message, icon="🚨")
        st.rerun()  # Re-run the script to re-enable buttons

if st.session_state.show_feedback:
    col1, col2, _ = st.columns([1, 1, 10])
    feedback_type = None
    if col1.button("👍", key="thumbs_up"):
        feedback_type = "👍 Thumbs Up"
        st.session_state["feedback_type"] = feedback_type
        utils.store_feedback(
            user_email=user_email,
            conversation_id=st.session_state["conversationId"],
            parent_message_id=st.session_state["parentMessageId"],
            user_message=st.session_state.user_prompt,
            feedback={"type": feedback_type},
            config=config_agent
        )
        st.session_state["show_feedback"] = False
        st.session_state["feedback_type"] = ""
        st.session_state["show_feedback_success"] = True
        st.rerun()
    if col2.button("👎", key="thumbs_down"):
        feedback_type = "👎 Thumbs Down"
        st.session_state["feedback_type"] = feedback_type

    additional_feedback = ""

    if st.session_state.get("feedback_type") == "👎 Thumbs Down":
        feedback_reason = st.selectbox(
            "Please select the reason for your feedback:",
            ["Not Relevant/Off Topic", "Not Accurate", "Not Enough Information", "Other"],
            key="feedback_selectbox"
        )
        if feedback_reason == "Other":
            additional_feedback = st.text_input("Please provide additional feedback:", key="additional_feedback_input")

        if st.button("Submit Feedback", key="submit_feedback_button"):
            if feedback_reason == "Other" and not additional_feedback:
                st.warning("Please provide additional feedback for 'Other'.")
            else:
                feedback_details = feedback_reason
                if additional_feedback:
                    feedback_details = additional_feedback

                utils.store_feedback(
                    user_email=user_email,
                    conversation_id=st.session_state["conversationId"],
                    parent_message_id=st.session_state["parentMessageId"],
                    user_message=st.session_state.user_prompt,
                    feedback={"type": st.session_state["feedback_type"], "reason": feedback_details},
                    config=config_agent
                )
                st.session_state["show_feedback"] = False
                st.session_state["feedback_type"] = ""
                st.session_state["feedback_reason"] = ""
                st.session_state["additional_feedback"] = ""
                st.session_state["show_feedback_success"] = True
                st.rerun()

if st.session_state.show_feedback_success:
    st.success("Thank you for your feedback!")

# Ensure the clear chat button remains visible at the bottom of the response only after authentication
if "token" in st.session_state:
    st.button("Clear Chat", on_click=clear_chat_history)

# Display remaining idle time before auto-clear
if "idle_time_left" in st.session_state:
    st.warning(f"Time left before chat clears: {st.session_state.idle_time_left:.0f} seconds", icon="⏰")

# Start the idle timer check thread
if auto_clear_session:
    if "idle_thread" not in st.session_state:
        idle_thread = threading.Thread(target=check_idle_time, daemon=True)
        idle_thread.start()
        st.session_state.idle_thread = idle_thread
