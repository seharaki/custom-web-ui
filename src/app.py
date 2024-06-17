from datetime import datetime, timedelta, timezone
import jwt
import streamlit as st
import utils

UTC = timezone.utc

# Init configuration
utils.retrieve_config_from_agent()

st.set_page_config(page_title="Amazon Q Business Custom UI")
st.title("Amazon Q Business Custom UI")

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""
    st.session_state["user_prompt"] = ""  # Clear the user prompt as well

oauth2 = utils.configure_oauth_component()
if "token" not in st.session_state:
    # If not, show authorize button
    redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    result = oauth2.authorize_button("Click here to login", scope="openid email", pkce="S256", redirect_uri=redirect_uri)
    if result and "token" in result:
        # If authorization successful, save token in session state
        st.session_state.token = result.get("token")
        # Retrieve the Identity Center token
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        st.rerun()
else:
    token = st.session_state.token
    refresh_token = token.get("refresh_token")  # saving the long lived refresh_token
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]
    if st.button("Refresh Cognito Token"):
        # If refresh token button is clicked or the token is expired, refresh the token
        token = oauth2.refresh_token(token, force=True)
        # Put the refresh token in the session state as it is not returned by Cognito
        if token.get("refresh_token"):
            token["refresh_token"] = refresh_token
        # Retrieve the Identity Center token
        st.session_state.token = token
        st.rerun()

    if "idc_jwt_token" not in st.session_state:
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
    elif st.session_state["idc_jwt_token"]["expires_at"] < datetime.now(UTC):
        # If the Identity Center token is expired, refresh the Identity Center token
        try:
            st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(st.session_state["idc_jwt_token"]["refreshToken"])
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        except Exception as e:
            st.error(f"Error refreshing Identity Center token: {e}. Please reload the page.")

    col1, col2 = st.columns([0.25, 0.25])

    with col1:
        st.write("Welcome: ", user_email)
    with col2:
        st.button("Clear Chat History", on_click=clear_chat_history)

    # Initialize the chat messages in the session state if it doesn't exist
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

    # User-provided prompt
    if prompt := st.chat_input(key="chat_input"):
        st.session_state.user_prompt = prompt  # Store the prompt in session state
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)
        st.session_state["show_feedback"] = False  # Hide feedback form when a new message is sent

    # If the last message is from the user, generate a response from the Q_backend
    if st.session_state.messages and st.session_state.messages[-1]["role"] == "user":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()
                response = utils.get_queue_chain(
                    st.session_state.user_prompt,  # Use the stored user prompt
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
            # Enable feedback form
            st.session_state["show_feedback"] = True
            st.session_state["show_feedback_success"] = False  # Hide success message

# Show feedback form after the assistant responds
if "show_feedback" not in st.session_state:
    st.session_state["show_feedback"] = False

if st.session_state["show_feedback"]:
    col1, col2, _ = st.columns([1, 1, 3])
    feedback_type = None
    if col1.button("👍", key="thumbs_up"):
        feedback_type = "👍 Thumbs Up"
        st.session_state["feedback_type"] = feedback_type
        # Store thumbs up feedback
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

                # Store feedback
                utils.store_feedback(
                    user_email=user_email,
                    conversation_id=st.session_state["conversationId"],
                    parent_message_id=st.session_state["parentMessageId"],
                    user_message=st.session_state.user_prompt,  # Pass the stored user prompt
                    feedback={"type": st.session_state["feedback_type"], "reason": feedback_details}
                )
                # Clear feedback state after submission
                st.session_state["show_feedback"] = False
                st.session_state["feedback_type"] = ""
                st.session_state["feedback_reason"] = ""
                st.session_state["additional_feedback"] = ""
                st.session_state["show_feedback_success"] = True  # Show success message
                st.experimental_rerun()

# Display success message if feedback was submitted
if "show_feedback_success" in st.session_state and st.session_state["show_feedback_success"]:
    st.success("Thank you for your feedback!")
