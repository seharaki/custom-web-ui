import datetime
import logging
import os
import json  # Import JSON module
import boto3
import jwt
import streamlit as st
import urllib3
from streamlit_oauth import OAuth2Component

logger = logging.getLogger()

# Configuration
APPCONFIG_APP_NAME = os.environ["APPCONFIG_APP_NAME"]
APPCONFIG_ENV_NAME = os.environ["APPCONFIG_ENV_NAME"]
APPCONFIG_CONF_NAME = os.environ["APPCONFIG_CONF_NAME"]
AMAZON_Q_APP_ID = None
IAM_ROLE = None
REGION = None
IDC_APPLICATION_ID = None
OAUTH_CONFIG = {}


def retrieve_config_from_agent():
    """
    Retrieve the configuration from the agent.
    """
    global IAM_ROLE, REGION, IDC_APPLICATION_ID, AMAZON_Q_APP_ID, OAUTH_CONFIG
    config = urllib3.request(
        "GET",
        f"http://localhost:2772/applications/{APPCONFIG_APP_NAME}/environments/{APPCONFIG_ENV_NAME}/configurations/{APPCONFIG_CONF_NAME}",
    ).json()
    IAM_ROLE = config["IamRoleArn"]
    REGION = config["Region"]
    IDC_APPLICATION_ID = config["IdcApplicationArn"]
    AMAZON_Q_APP_ID = config["AmazonQAppId"]
    OAUTH_CONFIG = config["OAuthConfig"]


def configure_oauth_component():
    """
    Configure the OAuth2 component for Cognito.
    """
    cognito_domain = OAUTH_CONFIG["CognitoDomain"]
    authorize_url = f"https://{cognito_domain}/oauth2/authorize"
    token_url = f"https://{cognito_domain}/oauth2/token"
    refresh_token_url = f"https://{cognito_domain}/oauth2/token"
    revoke_token_url = f"https://{cognito_domain}/oauth2/revoke"
    client_id = OAUTH_CONFIG["ClientId"]
    return OAuth2Component(client_id, None, authorize_url, token_url, refresh_token_url, revoke_token_url)


def refresh_iam_oidc_token(refresh_token):
    """
    Refresh the IAM OIDC token using the refresh token from Cognito.
    """
    client = boto3.client("sso-oidc", region_name=REGION)
    response = client.create_token_with_iam(
        clientId=IDC_APPLICATION_ID,
        grantType="refresh_token",
        refreshToken=refresh_token,
    )
    return response


def get_iam_oidc_token(id_token):
    """
    Get the IAM OIDC token using the Cognito ID token.
    """
    client = boto3.client("sso-oidc", region_name=REGION)
    response = client.create_token_with_iam(
        clientId=IDC_APPLICATION_ID,
        grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion=id_token,
    )
    return response


def assume_role_with_token(iam_token):
    """
    Assume IAM role using the IAM OIDC idToken.
    """
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
    """
    Create the Amazon Q client using IAM identity-aware AWS Session.
    """
    if not st.session_state.aws_credentials:
        assume_role_with_token(idc_id_token)
    elif st.session_state.aws_credentials["Expiration"] < datetime.datetime.now(datetime.UTC):
        assume_role_with_token(idc_id_token)

    session = boto3.Session(
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
    )
    return session.client("qbusiness", REGION)


def get_queue_chain(prompt_input, conversation_id, parent_message_id, token):
    """
    Invoke the Amazon Q chat_sync API and format the response for the UI.
    """
    # List available Bedrock models
    available_models = list_available_bedrock_models()
    st.warning("Available Bedrock Models:")
    for model in available_models:
        st.warning(f"Model ID: {model['modelId']}, Provider: {model['providerName']}, Model Name: {model['modelName']}")
    amazon_q = get_qclient(token)
    if conversation_id:
        answer = amazon_q.chat_sync(
            applicationId=AMAZON_Q_APP_ID,
            userMessage=prompt_input,
            conversationId=conversation_id,
            parentMessageId=parent_message_id,
        )
    else:
        answer = amazon_q.chat_sync(
            applicationId=AMAZON_Q_APP_ID, userMessage=prompt_input
        )

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

    return result


def get_bedrock_client():
    """
    Create a Bedrock client to use AWS Bedrock services.
    """
    session = boto3.Session(
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
    )
    return session.client("bedrock-runtime", region_name=REGION)


def list_available_bedrock_models():
    """
    List available models in AWS Bedrock.
    """
    bedrock_client = get_bedrock_client()
    response = bedrock_client.list_foundation_models()
    
    models = response.get("models", [])
    return models


def get_bedrock_response(prompt):
    """
    Send the prompt to AWS Bedrock (Claude LLM) and return the response.
    """
    bedrock_client = get_bedrock_client()
    
    # Bedrock uses the model ID and content
    response = bedrock_client.invoke_model(
        modelId="claude-v2",  # Replace with your actual model ID
        body=json.dumps({"prompt": prompt}),  # Payload with prompt
        contentType="application/json"
    )
    
    # Parse the response body
    response_body = response['body'].read().decode('utf-8')
    result = json.loads(response_body)

    return {
        "answer": result.get("outputText", ""),
        "references": "No sources available"  # Replace with appropriate source extraction if available
    }
