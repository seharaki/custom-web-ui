from datetime import datetime, timedelta, timezone
import jwt
import streamlit as st
import utils
from streamlit_feedback import streamlit_feedback

UTC = timezone.utc

# Init configuration
utils.retrieve_config_from_agent()

if "aws_credentials" not in st.session_state:
    st.session_state.aws_credentials = None

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

oauth2 = utils.configure_oauth_component()

if "token" not in st.session_state:
    redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    result = oauth2.authorize_button("Connect with Cognito", scope="openid", pkce="S256", redirect_uri=redirect_uri)
    if result and "token" in result:
        st.session_state.token = result.get("token")
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        st.rerun()
else:
    token = st.session_state["token"]
    refresh_token = token["refresh_token"]
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]

    if st.button("Refresh Cognito Token"):
        token = oauth2.refresh_token(token, force=True)
        token["refresh_token"] = refresh_token
        st.session_state.token = token
        st.rerun()

    if "idc_jwt_token" not in st.session_state:
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
    elif st.session_state["idc_jwt_token"]["expires_at"] < datetime.now(UTC):
        try:
            st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(st.session_state["idc_jwt_token"]["refreshToken"])
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        except Exception as e:
            st.error(f"Error refreshing Identity Center token: {e}. Please reload the page.")

    col1, col2 = st.columns([1,1])
    with col1:
        st.write("Welcome: ", user_email)
    with col2:
        st.button("Clear Chat History", on_click=clear_chat_history)

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

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    if prompt := st.chat_input():
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

    if st.session_state.messages[-1]["role"] != "assistant":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()

                # Fetch the response from Amazon Q
                q_response = utils.get_queue_chain(prompt, st.session_state["conversationId"], st.session_state["parentMessageId"], st.session_state["idc_jwt_token"]["idToken"])

                # Fetch the response from Bedrock (Claude LLM)
                bedrock_response = utils.get_bedrock_response(prompt)

                # Format the responses
                q_full_response = f"**Amazon Q Response:**\n{q_response['answer']}\n\n---\n{q_response.get('references', 'No sources')}"
                bedrock_full_response = f"**Claude LLM Response (Bedrock):**\n{bedrock_response['answer']}\n\n---\n{bedrock_response.get('references', 'No sources')}"

                # Display the Q response with a warning
                st.warning("Response from Amazon Q")
                placeholder.markdown(q_full_response)

                # Display the Bedrock response with a warning
                st.warning("Response from Bedrock (Claude LLM)")
                st.markdown(bedrock_full_response)

                # Save conversation states
                st.session_state["conversationId"] = q_response["conversationId"]
                st.session_state["parentMessageId"] = q_response["parentMessageId"]

        st.session_state.messages.append({"role": "assistant", "content": q_full_response})
        st.session_state.messages.append({"role": "assistant", "content": bedrock_full_response})

        feedback = streamlit_feedback(
            feedback_type="thumbs",
            optional_text_label="[Optional] Please provide an explanation",
        )
