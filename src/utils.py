import boto3
import datetime
import jwt
import streamlit as st
import urllib3

# Existing code remains the same ...

# This method create the Q client
def get_qclient(idc_id_token: str):
    if not st.session_state.aws_credentials:
        assume_role_with_token(idc_id_token)
    elif st.session_state.aws_credentials["Expiration"] < datetime.datetime.now(datetime.UTC):
        assume_role_with_token(idc_id_token)

    session = boto3.Session(
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
    )
    amazon_q = session.client("qbusiness", REGION)
    return amazon_q

# This code invokes chat_sync api and formats the response for UI
def get_queue_chain(prompt_input, conversation_id, parent_message_id, token):
    amazon_q = get_qclient(token)
    if conversation_id:
        answer = amazon_q.chat_sync(
            applicationId=AMAZON_Q_APP_ID,
            userMessage=prompt_input,
            conversationId=conversation_id,
            parentMessageId=parent_message_id,
        )
    else:
        answer = amazon_q.chat_sync(applicationId=AMAZON_Q_APP_ID, userMessage=prompt_input)

    result = {
        "answer": answer.get("systemMessage", ""),
        "conversationId": answer.get("conversationId", ""),
        "parentMessageId": answer.get("systemMessageId", ""),
    }

    if "sourceAttributions" in answer:
        valid_attributions = []
        for attr in answer["sourceAttributions"]:
            title = attr.get("title", "")
            url = attr.get("url", "")
            citation_number = attr.get("citationNumber", "")
            if title:
                valid_attributions.append(f"[{citation_number}] {title} ({url})")
        result["references"] = "\n\n".join(valid_attributions)

    return result

# Bedrock client for Claude LLM
def get_bedrock_client():
    session = boto3.Session(
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
    )
    return session.client("bedrock", REGION)

def get_bedrock_response(prompt):
    bedrock_client = get_bedrock_client()
    
    response = bedrock_client.invoke_model(
        modelId="claude-v2",
        body={"prompt": prompt},
        contentType="application/json"
    )
    
    result = response["body"]
    result = {
        "answer": result.get("text", ""),
        "references": "No sources available"
    }
    return result
