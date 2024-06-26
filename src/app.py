from datetime import datetime, timedelta, timezone
import jwt
import streamlit as st
import utils
 
# Title
title = "Virtual Assistant"
 
# Page Configuration
st.set_page_config(page_title=title, layout="wide")
st.title(title)
 
# Init configuration
config_agent = utils.retrieve_config_from_agent()
 
UTC = timezone.utc
 
hide_streamlit_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        </style>
        """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)
 
# Safety Messaging
safety_message = "X"
 
# Show Session Time
session_toggle = True
 
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
 
def get_remaining_session_time():
    if "idc_jwt_token" in st.session_state and "expires_at" in st.session_state["idc_jwt_token"]:
        expires_at = st.session_state["idc_jwt_token"]["expires_at"]
        remaining_time = expires_at - datetime.now(tz=UTC)
        return remaining_time
    return None
 
def refresh_token_if_needed():
    if "idc_jwt_token" in st.session_state:
        remaining_time = get_remaining_session_time()
        if remaining_time and remaining_time < timedelta(minutes=58):
            try:
                token = oauth2.refresh_token(st.session_state.token, force=True)
                # Store refresh token if available
                if "refresh_token" in token:
                    st.session_state.refresh_token = token["refresh_token"]
                else:
                    token["refresh_token"] = st.session_state.refresh_token
                # Retrieve the Identity Center token
                st.session_state.token = token
                st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(token["id_token"], config=config_agent)
                st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
            except Exception as e:
                st.error(f"Error refreshing token: {e}. Refresh the page.")

 
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
        st.rerun()
else:
    token = st.session_state.token
    refresh_token = st.session_state.get("refresh_token", token.get("refresh_token"))
    if not refresh_token:
        st.error("No refresh token available. Please log in again.")
        del st.session_state["token"]
        st.rerun()
 
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]
 
    # Automatic token refresh
    refresh_token_if_needed()
 
    col1, col2 = st.columns([1, 3])
 
    with col1:
        st.write("Logged in with DeviceID: ", user_email)
    with col2:
        st.button("Clear Chat", on_click=clear_chat_history)
 
    # Display remaining session time
    remaining_time = get_remaining_session_time()
    if remaining_time:
        if session_toggle:
            st.info(f"Session expires in: {remaining_time}")
 
    # Define sample questions
    sample_questions = [
        "What A",
        "How B",
        "What C",
        "What D",
        "What E"
    ]
 
    # Track which sample questions have been clicked
    if "clicked_samples" not in st.session_state:
        st.session_state.clicked_samples = []
 
    # Display sample question buttons if they haven't been clicked yet
    if token:
        remaining_questions = [q for q in sample_questions if q not in st.session_state.clicked_samples]
        if remaining_questions:
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
            cols = st.columns(len(remaining_questions))
            for idx, question in enumerate(remaining_questions):
                if cols[idx].button(question, key=question, help="Click to ask this question", use_container_width=True):
                    st.session_state.clicked_samples.append(question)
                    st.session_state.user_prompt = question
                    st.session_state.messages.append({"role": "user", "content": question})
                    st.experimental_rerun()
    # Add a horizontal line after the sample questions
    st.markdown("<hr>", unsafe_allow_html=True)
   
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
                    st.session_state["idc_jwt_token"]["idToken"],
                    config_agent
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
                response=full_response,
                config=config_agent
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
            feedback={"type": feedback_type},
            config = config_agent
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
                    feedback={"type": st.session_state["feedback_type"], "reason": feedback_details},
                    config = config_agent
                )
                st.session_state["show_feedback"] = False
                st.session_state["feedback_type"] = ""
                st.session_state["feedback_reason"] = ""
                st.session_state["additional_feedback"] = ""
                st.session_state["show_feedback_success"] = True
                st.experimental_rerun()
 
if "show_feedback_success" in st.session_state and st.session_state["show_feedback_success"]:
    st.success("Thank you for your feedback!")