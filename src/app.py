from datetime import datetime, timedelta, timezone
import jwt
import streamlit as st
import utils

UTC = timezone.utc

# Safety Messaging
SAFETY_MESSAGE = '''At W, we are committed to a safety-first mindset by following all safety policies and procedures.  The Chatbot may describe a task common to a xxx facility.  Before attempting to replicate:
 
·        Be certain that potential hazardous energy is controlled before breaking the plane of the machine and reaching in by obtaining exclusive control through Lockout Tagout/Energy Safe Position (ESP). 
·        Ensure proper personal protective equipment (PPE) is employed.
·        Consult the machine specific xx, Lockout Tagout and ESP procedures, your Supervisor or Safety Manager if you are unsure of any safety requirements of the task. 
·        Notify any employees in the area that may be affected prior to beginning the task.
If there are safety concerns identified involving the task, please notify your Supervisor or submit it through the Concern reporting system.'''

# Title
TITLE = "X Virtual Operator Chatbot"

# Sample questions
SAMPLE_QUESTIONS = [
    "This is sample question 1",
    "This is sample question 2",
    "This is sample question 3"
]

def initialize_app():
    """Initializes the app configuration and sets the page title."""
    utils.retrieve_config_from_agent()
    st.set_page_config(page_title=TITLE)
    st.title(TITLE)

def clear_chat_history():
    """Clears the chat history."""
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""
    st.session_state["user_prompt"] = ""

def handle_oauth():
    """Handles the OAuth2 authentication and token refresh."""
    oauth2 = utils.configure_oauth_component()
    if "token" not in st.session_state:
        redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
        result = oauth2.authorize_button("Start Chatting", scope="openid email", pkce="S256", redirect_uri=redirect_uri)
        if result and "token" in result:
            st.session_state.token = result.get("token")
            st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"])
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
            st.rerun()
    else:
        token = st.session_state.token
        refresh_token = token.get("refresh_token")
        user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]

        if "idc_jwt_token" not in st.session_state:
            st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"])
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        elif st.session_state["idc_jwt_token"]["expires_at"] < datetime.now(UTC):
            try:
                st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(st.session_state["idc_jwt_token"]["refreshToken"])
                st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
            except Exception as e:
                st.error(f"Error refreshing Identity Center token: {e}. Please reload the page.")
        return user_email, token
    return None, None

def display_user_info_and_clear_button(user_email):
    """Displays the user email and a button to clear the chat history."""
    col1, col2 = st.columns([1, 1])
    with col1:
        st.write("Logged in with DeviceID: ", user_email)
    with col2:
        st.button("Clear Chat", on_click=clear_chat_history)

def display_sample_questions(token):
    """Displays sample questions if the user is authenticated."""
    if token:
        if "clicked_samples" not in st.session_state:
            st.session_state.clicked_samples = []
        remaining_questions = [q for q in SAMPLE_QUESTIONS if q not in st.session_state.clicked_samples]
        if remaining_questions:
            st.markdown("<div style='font-size:16px;'>Frequently Asked Questions</div>", unsafe_allow_html=True)
            cols = st.columns(len(remaining_questions))
            for idx, question in enumerate(remaining_questions):
                if cols[idx].button(question, key=question, help="Click to ask this question", use_container_width=True):
                    st.session_state.clicked_samples.append(question)
                    st.session_state.user_prompt = question
                    st.session_state.messages.append({"role": "user", "content": question})
                    st.experimental_rerun()

def display_chat_messages():
    """Displays the chat messages."""
    if "messages" not in st.session_state:
        st.session_state["messages"] = [{"role": "assistant", "content": "How can I help you?"}]
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

def handle_user_input():
    """Handles user input from the chat input box."""
    if prompt := st.chat_input(key="chat_input"):
        st.session_state.user_prompt = prompt
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)
        st.session_state["show_feedback"] = False
        process_user_input()

def process_user_input():
    """Processes the user's input by generating a response and storing the message."""
    if st.session_state.messages and st.session_state.messages[-1]["role"] == "user":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()
                response = utils.get_queue_chain(
                    st.session_state.user_prompt,
                    st.session_state["conversationId"],
                    st.session_state["parentMessageId"],
                    st.session_state["idc_jwt_token"]["idToken"]
                )
                full_response = f"""{response["answer"]}\n\n---\n{response.get("references", "No sources")}"""
                placeholder.markdown(full_response)
                st.session_state["conversationId"] = response["conversationId"]
                st.session_state["parentMessageId"] = response["parentMessageId"]
            st.session_state.messages.append({"role": "assistant", "content": full_response})
            utils.store_message_response(
                user_email=jwt.decode(st.session_state.token["id_token"], options={"verify_signature": False})["email"],
                conversation_id=st.session_state["conversationId"],
                parent_message_id=st.session_state["parentMessageId"],
                user_message=st.session_state.user_prompt,
                response=full_response
            )
            st.session_state["show_feedback"] = True
            st.session_state["show_feedback_success"] = False
            st.warning(SAFETY_MESSAGE, icon="🚨")

def display_feedback_buttons():
    """Displays feedback buttons and handles feedback submission."""
    if "show_feedback" not in st.session_state:
        st.session_state["show_feedback"] = False
    if st.session_state["show_feedback"]:
        col1, col2, _ = st.columns([1, 1, 10])
        feedback_type = None
        if col1.button("👍", key="thumbs_up"):
            feedback_type = "👍 Thumbs Up"
            st.session_state["feedback_type"] = feedback_type
            store_feedback(feedback_type)
        if col2.button("👎", key="thumbs_down"):
            feedback_type = "👎 Thumbs Down"
            st.session_state["feedback_type"] = feedback_type

        if st.session_state.get("feedback_type") == "👎 Thumbs Down":
            feedback_reason = st.selectbox(
                "Please select the reason for your feedback:",
                ["Not Relevant/Off Topic", "Not Accurate", "Not Enough Information", "Other"],
                key="feedback_selectbox"
            )
            additional_feedback = ""
            if feedback_reason == "Other":
                additional_feedback = st.text_input("Please provide additional feedback:", key="additional_feedback_input")
            if st.button("Submit Feedback", key="submit_feedback_button"):
                if feedback_reason == "Other" and not additional_feedback:
                    st.warning("Please provide additional feedback for 'Other'.")
                else:
                    feedback_details = additional_feedback if additional_feedback else feedback_reason
                    store_feedback(feedback_type, feedback_details)

def store_feedback(feedback_type, feedback_details=None):
    """Stores user feedback."""
    utils.store_feedback(
        user_email=jwt.decode(st.session_state.token["id_token"], options={"verify_signature": False})["email"],
        conversation_id=st.session_state["conversationId"],
        parent_message_id=st.session_state["parentMessageId"],
        user_message=st.session_state.user_prompt,
        feedback={"type": feedback_type, "reason": feedback_details}
    )
    st.session_state["show_feedback"] = False
    st.session_state["feedback_type"] = ""
    st.session_state["feedback_reason"] = ""
    st.session_state["additional_feedback"] = ""
    st.session_state["show_feedback_success"] = True
    st.experimental_rerun()

def display_feedback_success():
    """Displays feedback success message."""
    if "show_feedback_success" in st.session_state and st.session_state["show_feedback_success"]:
        st.success("Thank you for your feedback!")
        st.session_state["show_feedback_success"] = False

# Initialize app
initialize_app()

# Handle OAuth and get user information
user_email, token = handle_oauth()

# Display user info and clear chat button
if user_email:
    display_user_info_and_clear_button(user_email)

# Display sample questions
display_sample_questions(token)

# Display chat messages
display_chat_messages()

# Handle user input
handle_user_input()

# Display feedback buttons
display_feedback_buttons()

# Display feedback success message
display_feedback_success()
