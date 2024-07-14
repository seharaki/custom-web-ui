from datetime import datetime, timedelta, timezone
import jwt
import jwt.algorithms
import streamlit as st
import utils
import time
from streamlit_feedback import streamlit_feedback
from streamlit_modal import Modal
from PIL import Image, UnidentifiedImageError
from botocore.exceptions import ClientError

UTC = timezone.utc

# Title
title = "x"
help_message = "X"

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

# Styling for thumbs up and thumbs down buttons
st.markdown("""
<style>
.element-container:has(#thumbs-up-span) + div button {
    font-size: 32px !important;
    width: 100% !important;  /* Adjust the width as needed */
    margin-right: 2px !important;  /* Add margin to separate buttons */
}
.element-container:has(#thumbs-down-span) + div button {
    font-size: 32px !important;
    width: 130% !important;  /* Adjust the width as needed */
}
</style>
""", unsafe_allow_html=True)

# Modal setup
help_modal = Modal("How to use the chatbot?", key="help-modal", padding=15,max_width=950)

# Safety Messaging
safety_message = "X"

# Show Session Time
session_toggle = False

# Init configuration
config_agent = utils.retrieve_config_from_agent()
if "aws_credentials" not in st.session_state:
    st.session_state.aws_credentials = None

# Initialize session state variables
if "messages" not in st.session_state:
    st.session_state.messages = []
if "response" not in st.session_state:
    st.session_state.response = ""
if "resources" not in st.session_state:
    st.session_state.resources = ""
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
if "thinking" not in st.session_state:
    st.session_state.thinking = False
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "warning_message" not in st.session_state:
    st.session_state.warning_message = False
if "rerun" not in st.session_state:
    st.session_state.rerun = False
if "oauth_init" not in st.session_state:
    st.session_state.oauth_init = False

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""
    st.session_state["show_feedback_success"] = False
    st.session_state["warning_message"] = False

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
        if (end_pos == -1):
            end_pos = len(part)
        url = part[:end_pos].strip()
        if url.endswith(".json"):
            url = url[:-5]  # Remove '.json' from the end of the URL
        encoded_url = url.replace(' ', '%20')
        rest = part[end_pos:]
        encoded_references += "URL: " + encoded_url + rest
    return encoded_references

oauth2 = utils.configure_oauth_component(config_agent.OAUTH_CONFIG)
if "token" not in st.session_state:
    redirect_uri = f"https://{config_agent.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    st.warning(st.session_state["oauth_init"])
    result = oauth2.authorize_button("Start Chatting", scope="openid email offline_access", pkce="S256", redirect_uri=redirect_uri)
    if not st.session_state.oauth_init:
        st.session_state.oauth_init = True
        st.rerun()
    st.warning("Outside the if statement")
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
    col1, col2, col3 = st.columns([1, 1, 3])

    with col1:
        st.write("Logged in with DeviceID: ", user_email)
    with col2:
        open_help_modal = st.button("Help", disabled=st.session_state.thinking)
        if open_help_modal:
            help_modal.open()

    if help_modal.is_open():
        with help_modal.container():
            st.markdown('<img src="./app/static/help.jpg" style="width:100%">', unsafe_allow_html=True)
            st.write("Here is how to use this chatbot, click the FAQs at the top")

    if "messages" not in st.session_state or not st.session_state.messages:
        st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]

    # Display remaining session time
    remaining_time = get_remaining_session_time()
    if remaining_time:
        if session_toggle:
            st.info(f"Session expires in: {remaining_time}")

    # Define sample questions
    sample_questions = [
        "What A?",
        "How dB?",
        "What C",
        "What D?",
        "What E?"
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
            disabled=st.session_state.thinking,
            help="Click to ask",
            on_click=lambda q=question: set_rerun_flag(q)
        )

def set_rerun_flag(question):
    st.session_state.clicked_samples.append(question)
    st.session_state.user_prompt = question
    st.session_state.messages.append({"role": "user", "content": question})
    st.session_state.thinking = True
    st.session_state.rerun = True

if st.session_state.rerun:
    st.session_state.rerun = False
    st.rerun()

# Add a horizontal line after the sample questions
st.markdown("<hr>", unsafe_allow_html=True)

# Display the chat messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

# User-provided prompt
if st.session_state.authenticated:  # Only show chat input if authenticated
    if prompt := st.chat_input(key="chat_input"):
        st.session_state.user_prompt = prompt
        st.session_state.messages.append({"role": "user", "content": prompt})
        st.session_state.thinking = True  # Disable buttons when user sends a message
        st.rerun()

if st.session_state.messages and st.session_state.messages[-1]["role"] == "user":
    st.session_state.thinking = True
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            placeholder = st.empty()
            try:
                response = utils.get_queue_chain(
                    st.session_state.user_prompt,
                    st.session_state["conversationId"],
                    st.session_state["parentMessageId"],
                    st.session_state["idc_jwt_token"]["idToken"],
                    config_agent
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'ValidationException':
                    error_message = str(e)
                    # Retry the request with updated parentMessageId
                    st.session_state["conversationId"] = ""
                    response = utils.get_queue_chain(
                        st.session_state.user_prompt,
                        st.session_state["conversationId"],
                        st.session_state["parentMessageId"],
                        st.session_state["idc_jwt_token"]["idToken"],
                        config_agent
                    )
                else:
                    raise e

            if "references" in response:
                full_response = f"""{response["answer"]}\n\n---\n{encode_urls_in_references(response["references"])}"""
                st.session_state.resources = encode_urls_in_references(response["references"])
            else:
                full_response = f"""{response["answer"]}\n\n---\nNo sources"""
            placeholder.markdown(full_response)
            st.session_state["conversationId"] = response["conversationId"]
            st.session_state["parentMessageId"] = response["parentMessageId"]
            st.session_state.response = response["answer"]

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
        st.session_state.thinking = False
        st.session_state.warning_message = True
        st.rerun()  # Re-run the script to re-enable buttons

if st.session_state.show_feedback:
    col1, col2, _ = st.columns([1, 1, 10])
    feedback_type = None

    # Ensure the thumbs up and thumbs down buttons do not show for the initial message
    last_message = st.session_state.messages[-1]["content"] if st.session_state.messages else ""
    if last_message != "How may I assist you today?":
        with col1:
            st.markdown('<span id="thumbs-up-span"></span>', unsafe_allow_html=True)
            if st.button("👍 Thumbs Up", key="thumbs_up"):
                feedback_type = "👍 Thumbs Up"
                st.session_state["feedback_type"] = feedback_type
                utils.store_feedback(
                    user_email=user_email,
                    conversation_id=st.session_state["conversationId"],
                    parent_message_id=st.session_state["parentMessageId"],
                    user_message=st.session_state.user_prompt,
                    feedback={"type": feedback_type},
                    response=st.session_state.response,
                    references=st.session_state.resources,
                    config=config_agent
                )
                st.session_state["show_feedback"] = False
                st.session_state["feedback_type"] = ""
                st.session_state["show_feedback_success"] = True
                st.rerun()

        with col2:
            st.markdown('<span id="thumbs-down-span"></span>', unsafe_allow_html=True)
            if st.button("👎 Thumbs Down", key="thumbs_down"):
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
                        response=st.session_state.response,
                        references=st.session_state.resources,
                        config=config_agent
                    )
                    st.session_state["show_feedback"] = False
                    st.session_state["feedback_type"] = ""
                    st.session_state["feedback_reason"] = ""
                    st.session_state["additional_feedback"] = ""
                    st.session_state.response = ""
                    st.session_state.resources = ""
                    st.session_state["show_feedback_success"] = True
                    st.rerun()

if st.session_state.show_feedback_success:
    st.success("Thank you for your feedback!")

if st.session_state.warning_message:
    st.warning(safety_message, icon="🚨")

# Ensure the clear chat button remains visible at the bottom of the response only after authentication
if "token" in st.session_state:
    st.button("Clear Chat", on_click=clear_chat_history)
