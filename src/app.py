from datetime import datetime, timedelta, timezone
import jwt
import streamlit as st
import utils
from urllib.parse import urlencode

UTC = timezone.utc

# Safety Messaging
safety_message = '''At W, we are committed to a safety-first mindset by following all safety policies and procedures. The Chatbot may describe a task common to a xxx facility. Before attempting to replicate:
 
· Be certain that potential hazardous energy is controlled before breaking the plane of the machine and reaching in by obtaining exclusive control through Lockout Tagout/Energy Safe Position (ESP). 
· Ensure proper personal protective equipment (PPE) is employed.
· Consult the machine specific xx, Lockout Tagout and ESP procedures, your Supervisor or Safety Manager if you are unsure of any safety requirements of the task. 
· Notify any employees in the area that may be affected prior to beginning the task.
If there are safety concerns identified involving the task, please notify your Supervisor or submit it through the Concern reporting system.'''

# Title
title = "X Virtual Operator Chatbot"

# Init configuration
utils.retrieve_config_from_agent()

st.set_page_config(page_title=title)
st.title(title)

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""
    st.session_state["user_prompt"] = ""  # Initialize user prompt

# Function to perform OAuth2 authorization
def oauth2_authorize():
    redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    client_id = utils.OAUTH_CONFIG['ClientId']  # Retrieve client_id from configuration
    authorize_url = utils.OAUTH_CONFIG['AuthorizeUrl']  # Add this to your config if not already there
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'openid email',
        'redirect_uri': redirect_uri,
        'state': 'random_state_string',  # Use a proper state value
        'code_challenge': 'S256_challenge',  # Generate a PKCE challenge
        'code_challenge_method': 'S256'
    }
    authorization_url = f"{authorize_url}?{urlencode(params)}"
    st.experimental_set_query_params(redirect=authorization_url)

# Function to handle the OAuth2 callback
def handle_oauth2_callback():
    query_params = st.query_params
    if 'code' in query_params:
        code = query_params['code'][0]
        redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
        token_url = utils.OAUTH_CONFIG['TokenUrl']  # Add this to your config if not already there
        client_id = utils.OAUTH_CONFIG['ClientId']
        client_secret = utils.OAUTH_CONFIG.get('ClientSecret', '')  # Use client_secret if required
        token_response = utils.fetch_token(
            token_url=token_url,
            code=code,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri
        )
        st.session_state.token = token_response
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        st.experimental_rerun()

# Check if user is authenticated, if not, perform OAuth2 authorization
if "token" not in st.session_state:
    handle_oauth2_callback()
    if "token" not in st.session_state:
        oauth2_authorize()

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

    col1, col2 = st.columns([1, 1])

    with col1:
        st.write("Logged in with DeviceID: ", user_email)
    with col2:
        st.button("Clear Chat", on_click=clear_chat_history)

    # Define sample questions
    sample_questions = [
        "This is sample question 1",
        "This is sample question 2",
        "This is sample question 3"
    ]

    # Track which sample questions have been clicked
    if "clicked_samples" not in st.session_state:
        st.session_state.clicked_samples = []

    # Display sample question buttons if they haven't been clicked yet
    if token:
        remaining_questions = [q for q in sample_questions if q not in st.session_state.clicked_samples]
        if remaining_questions:
            st.markdown("<div style='font-size:16px;'>Frequently Asked Questions</div>", unsafe_allow_html=True)
            cols = st.columns(len(remaining_questions))
            for idx, question in enumerate(remaining_questions):
                if cols[idx].button(question, key=question, help="Click to ask this question", use_container_width=True):
                    st.session_state.clicked_samples.append(question)
                    st.session_state.user_prompt = question
                    st.session_state.messages.append({"role": "user", "content": question})
                    st.experimental_rerun()

    if "messages" not in st.session_state:
        st.session_state["messages"] = [{"role": "assistant", "content": "How can I help you?"}]

    if "conversationId" not in st.session_state:
        st.session_state["conversationId"] = ""

    if "parentMessageId" not in st.session_state:
        st.session_state["parentMessageId"] = ""

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    if "questions" not in st.session_state:
        st.session_state.questions = []

    if "answers" not in st.session_state:
        st.session_state.answers = []

    if "input" not in st.session_state:
        st.session_state.input = ""

    if "user_prompt" not in st.session_state:
        st.session_state.user_prompt = ""

    # Display the chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    # Handle user input from the chat input box
    if prompt := st.chat_input(key="chat_input"):
        st.session_state.user_prompt = prompt
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)
        st.session_state["show_feedback"] = False

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
                if "references" in response:
                    full_response = f"""{response["answer"]}\n\n---\n{response["references"]}"""
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
                response=full_response
            )
            st.session_state["show_feedback"] = True
            st.session_state["show_feedback_success"] = False
            st.warning(safety_message, icon="🚨")

if "show_feedback" not in st.session_state:
    st.session_state["show_feedback"] = False

if st.session_state["show_feedback"]:
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
            feedback={"type": feedback_type}
        )
        st.session_state["show_feedback"] = False
        st.session_state["feedback_type"] = ""
        st.session_state["show_feedback_success"] = True
        st.experimental_rerun()
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
                    feedback={"type": st.session_state["feedback_type"], "reason": feedback_details}
                )
                st.session_state["show_feedback"] = False
                st.session_state["feedback_type"] = ""
                st.session_state["feedback_reason"] = ""
                st.session_state["additional_feedback"] = ""
                st.session_state["show_feedback_success"] = True
                st.experimental_rerun()

if "show_feedback_success" in st.session_state and st.session_state["show_feedback_success"]:
    st.success("Thank you for your feedback!")
    st.session_state["show_feedback_success"] = False
