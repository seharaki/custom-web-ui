import datetime
import logging
import os
import json
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
    st.warning("Attempting to retrieve configuration from the agent.")
    try:
        config = urllib3.request(
            "GET",
            f"http://localhost:2772/applications/{APPCONFIG_APP_NAME}/environments/{APPCONFIG_ENV_NAME}/configurations/{APPCONFIG_CONF_NAME}",
        ).json()
        IAM_ROLE = config["IamRoleArn"]
        REGION = config["Region"]
        IDC_APPLICATION_ID = config["IdcApplicationArn"]
        AMAZON_Q_APP_ID = config["AmazonQAppId"]
        OAUTH_CONFIG = config["OAuthConfig"]
        st.warning(f"Configuration retrieved successfully. IAM_ROLE: {IAM_ROLE}, REGION: {REGION}")
    except Exception as e:
        st.warning(f"Error retrieving configuration: {e}")


def configure_oauth_component():
    """
    Configure the OAuth2 component for Cognito.
    """
    st.warning("Configuring OAuth2 component.")
    try:
        cognito_domain = OAUTH_CONFIG["CognitoDomain"]
        authorize_url = f"https://{cognito_domain}/oauth2/authorize"
        token_url = f"https://{cognito_domain}/oauth2/token"
        refresh_token_url = f"https://{cognito_domain}/oauth2/token"
        revoke_token_url = f"https://{cognito_domain}/oauth2/revoke"
        client_id = OAUTH_CONFIG["ClientId"]
        st.warning(f"OAuth2 Component Configured with Client ID: {client_id}")
        return OAuth2Component(client_id, None, authorize_url, token_url, refresh_token_url, revoke_token_url)
    except Exception as e:
        st.warning(f"Error configuring OAuth2 component: {e}")
        return None


def refresh_iam_oidc_token(refresh_token):
    """
    Refresh the IAM OIDC token using the refresh token from Cognito.
    """
    st.warning("Attempting to refresh IAM OIDC token.")
    try:
        client = boto3.client("sso-oidc", region_name=REGION)
        response = client.create_token_with_iam(
            clientId=IDC_APPLICATION_ID,
            grantType="refresh_token",
            refreshToken=refresh_token,
        )
        st.warning("IAM OIDC token refreshed successfully.")
        return response
    except Exception as e:
        st.warning(f"Error refreshing IAM OIDC token: {e}")
        return None


def get_iam_oidc_token(id_token):
    """
    Get the IAM OIDC token using the Cognito ID token.
    """
    st.warning("Attempting to get IAM OIDC token.")
    try:
        client = boto3.client("sso-oidc", region_name=REGION)
        response = client.create_token_with_iam(
            clientId=IDC_APPLICATION_ID,
            grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=id_token,
        )
        st.warning("IAM OIDC token retrieved successfully.")
        return response
    except Exception as e:
        st.warning(f"Error getting IAM OIDC token: {e}")
        return None


def assume_role_with_token(iam_token):
    """
    Assume IAM role using the IAM OIDC idToken.
    """
    st.warning("Attempting to assume role with IAM token.")
    try:
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
        st.warning(f"Assumed role successfully. Credentials: {st.session_state.aws_credentials}")
    except Exception as e:
        st.warning(f"Error assuming role: {e}")
        st.session_state.aws_credentials = None


def get_qclient(idc_id_token):
    """
    Create the Amazon Q client using IAM identity-aware AWS Session.
    """
    st.warning("Attempting to create Amazon Q client.")
    if not st.session_state.aws_credentials:
        st.warning("AWS credentials not found. Attempting to assume role.")
        assume_role_with_token(idc_id_token)
    else:
        st.warning(f"Using existing credentials: {st.session_state.aws_credentials}")

    if st.session_state.aws_credentials:
        try:
            session = boto3.Session(
                aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
                aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
                aws_session_token=st.session_state.aws_credentials["SessionToken"],
            )
            st.warning("Amazon Q client created successfully.")
            return session.client("qbusiness", REGION)
        except Exception as e:
            st.warning(f"Error creating Amazon Q client: {e}")
            return None
    else:
        st.warning("Failed to obtain valid AWS credentials.")
        return None


def get_bedrock_client(service="bedrock-runtime"):
    """
    Create a Bedrock or Bedrock Runtime client to use AWS Bedrock services.
    """
    st.warning(f"Attempting to create {service} client.")
    if not st.session_state.aws_credentials:
        st.warning("AWS credentials not found. Assuming role again.")
        assume_role_with_token(st.session_state["idc_jwt_token"]["idToken"])

    if st.session_state.aws_credentials:
        try:
            session = boto3.Session(
                aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
                aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
                aws_session_token=st.session_state.aws_credentials["SessionToken"],
            )
            st.warning(f"{service} client created successfully.")
            return session.client(service, region_name=REGION)
        except Exception as e:
            st.warning(f"Error creating {service} client: {e}")
            return None
    else:
        st.warning(f"Failed to obtain valid AWS credentials for {service}.")
        return None


def list_available_bedrock_models():
    """
    List available models in AWS Bedrock.
    """
    st.warning("Attempting to list available Bedrock models.")
    bedrock_client = get_bedrock_client(service="bedrock")  # Use the `bedrock` client for listing models
    if not bedrock_client:
        st.warning("Failed to create Bedrock client.")
        return []

    try:
        response = bedrock_client.list_foundation_models()  # This API is available in the `bedrock` client
        models = response.get("models", [])
        st.warning(f"Models retrieved: {models}")
        return models
    except Exception as e:
        st.warning(f"Error listing Bedrock models: {e}")
        return []


def get_bedrock_response(prompt):
    """
    Send the prompt to AWS Bedrock (Claude LLM) and return the response.
    """
    st.warning("Attempting to send prompt to Bedrock.")
    bedrock_client = get_bedrock_client(service="bedrock-runtime")  # Use `bedrock-runtime` for invoking models
    if not bedrock_client:
        st.warning("Failed to create Bedrock client.")
        return {"answer": "Error: Bedrock client not available", "references": ""}

    try:
        response = bedrock_client.invoke_model(
            modelId="claude-v2",  # Replace with your actual model ID
            body=json.dumps({"prompt": prompt}),
            contentType="application/json"
        )
        response_body = response['body'].read().decode('utf-8')
        result = json.loads(response_body)

        st.warning(f"Bedrock response received: {result}")
        return {
            "answer": result.get("outputText", ""),
            "references": "No sources available"
        }

    except Exception as e:
        st.warning(f"Error invoking Bedrock model: {e}")
        return {"answer": "Error: Failed to invoke Bedrock model", "references": ""}
