import datetime
import logging
import os
import json
import boto3
import jwt
import streamlit as st
from retrying import retry

logger = logging.getLogger()

# Configuration
APPCONFIG_APP_NAME = os.environ["APPCONFIG_APP_NAME"]
APPCONFIG_ENV_NAME = os.environ["APPCONFIG_ENV_NAME"]
APPCONFIG_CONF_NAME = os.environ["APPCONFIG_CONF_NAME"]
IAM_ROLE = None
REGION = None
IDC_APPLICATION_ID = None
AMAZON_Q_APP_ID = None
OAUTH_CONFIG = {}
BEDROCK_KB_ID = "your_knowledge_base_id"  # Replace with your Bedrock Knowledge Base ID


def retrieve_config_from_agent():
    global IAM_ROLE, REGION, IDC_APPLICATION_ID, AMAZON_Q_APP_ID, OAUTH_CONFIG
    config = boto3.client("appconfigdata").get_latest_configuration(
        Application=APPCONFIG_APP_NAME,
        Environment=APPCONFIG_ENV_NAME,
        Configuration=APPCONFIG_CONF_NAME,
    )
    IAM_ROLE = config["IamRoleArn"]
    REGION = config["Region"]
    IDC_APPLICATION_ID = config["IdcApplicationArn"]
    AMAZON_Q_APP_ID = config["AmazonQAppId"]
    OAUTH_CONFIG = config["OAuthConfig"]


def assume_role_with_token(iam_token):
    decoded_token = jwt.decode(iam_token, options={"verify_signature": False})
    sts_client = boto3.client("sts", region_name=REGION)
    response = sts_client.assume_role(
        RoleArn=IAM_ROLE,
        RoleSessionName="qapp",
        ProvidedContexts=[
            {
                "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                "ContextAssertion": decoded_token["sts:identity_context"],
            }
        ],
    )
    st.session_state.aws_credentials = response["Credentials"]


def get_qclient(idc_id_token):
    if not st.session_state.aws_credentials:
        assume_role_with_token(idc_id_token)
    session = boto3.Session(
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
    )
    return session.client("qbusiness", region_name=REGION)


def get_queue_chain(prompt_input, conversation_id, parent_message_id, token):
    st.warning("Attempting to invoke Amazon Q ChatSync API.")
    try:
        amazon_q = get_qclient(token)
        if not amazon_q:
            st.warning("Failed to create Amazon Q client.")
            return None

        if conversation_id:
            answer = amazon_q.chat_sync(
                applicationId=AMAZON_Q_APP_ID,
                userMessage=prompt_input,
                conversationId=conversation_id,
                parentMessageId=parent_message_id,
            )
        else:
            answer = amazon_q.chat_sync(applicationId=AMAZON_Q_APP_ID, userMessage=prompt_input)

        system_message = answer.get("systemMessage", "")
        conversation_id = answer.get("conversationId", "")
        parent_message_id = answer.get("systemMessageId", "")
        result = {
            "answer": system_message,
            "conversationId": conversation_id,
            "parentMessageId": parent_message_id,
        }

        if "sourceAttributions" in answer:
            attributions = answer["sourceAttributions"]
            valid_attributions = []

            for attr in attributions:
                title = attr.get("title", "")
                url = attr.get("url", "")
                citation_number = attr.get("citationNumber", "")
                attribution_text = []
                if citation_number:
                    attribution_text.append(f"[{citation_number}]")
                if title:
                    attribution_text.append(f"Title: {title}")
                if url:
                    attribution_text.append(f", URL: {url}")

                valid_attributions.append("".join(attribution_text))

            result["references"] = "\n\n".join(valid_attributions)

        st.warning(f"Amazon Q chat_sync API invoked successfully. Response: {result}")
        return result

    except Exception as e:
        st.warning(f"Error invoking Amazon Q ChatSync API: {e}")
        return None


def get_bedrock_client():
    session = boto3.Session()
    return session.client("bedrock", region_name=REGION)


def get_bedrock_kb_response(prompt):
    bedrock_client = get_bedrock_client()
    try:
        response = bedrock_client.retrieve_and_generate(
            input={"text": prompt},
            retrieveAndGenerateConfiguration={
                "type": "KNOWLEDGE_BASE",
                "knowledgeBaseConfiguration": {
                    "knowledgeBaseId": BEDROCK_KB_ID,  # Use Bedrock Knowledge Base ID
                    "modelArn": f"arn:aws:bedrock:{REGION}::foundation-model/anthropic.claude-3",
                },
            },
        )
        return {"answer": response["output"]["text"], "references": response.get("citations", [])}
    except Exception as e:
        return {"answer": f"Error retrieving Bedrock response: {e}", "references": ""}


def list_available_bedrock_models():
    bedrock_client = get_bedrock_client()
    try:
        response = bedrock_client.list_foundation_models()
        models = response.get("models", [])
        st.warning(f"Models retrieved: {models}")
        return models
    except Exception as e:
        st.warning(f"Error listing Bedrock models: {e}")
        return []


def refresh_iam_oidc_token(refresh_token):
    client = boto3.client("sso-oidc", region_name=REGION)
    response = client.create_token_with_iam(
        clientId=IDC_APPLICATION_ID,
        grantType="refresh_token",
        refreshToken=refresh_token,
    )
    return response


def get_iam_oidc_token(id_token):
    client = boto3.client("sso-oidc", region_name=REGION)
    response = client.create_token_with_iam(
        clientId=IDC_APPLICATION_ID,
        grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion=id_token,
    )
    return response
