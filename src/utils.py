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
    This is only required for the Q Business call.
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
    Create the Amazon Q client using IAM identity-aware AWS Session (using assumed role).
    """
    st.warning("Attempting to create Amazon Q client (with assumed role).")
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


def get_queue_chain(prompt_input, conversation_id, parent_message_id, token):
    """
    Invoke the Amazon Q chat_sync API and format the response for the UI.
    """
    st.warning("Attempting to invoke Amazon Q chat_sync API.")
    # List available Bedrock models
    available_models = list_available_bedrock_models()
    st.warning("Available Bedrock Models:")
    for model in available_models:
        st.warning(f"Model ID: {model['modelId']}, Provider: {model['providerName']}, Model Name: {model['modelName']}")
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

        st.warning(f"Amazon Q chat_sync API invoked successfully. Response: {result}")
        return result

    except Exception as e:
        st.warning(f"Error invoking Amazon Q chat_sync API: {e}")
        return None


def get_bedrock_client():
    """
    Create a Bedrock client to use AWS Bedrock services (no role assumption required).
    """
    st.warning("Attempting to create Bedrock client.")
    try:
        # No need to assume role; use default credentials
        session = boto3.Session()
        st.warning("Bedrock client created successfully.")
        return session.client("bedrock", region_name=REGION)
    except Exception as e:
        st.warning(f"Error creating Bedrock client: {e}")
        return None


def list_available_bedrock_models():
    """
    List available models in AWS Bedrock using the correct method from the documentation.
    """
    st.warning("Attempting to list available Bedrock models.")
    bedrock_client = get_bedrock_client()  # Ensure we are using the correct client for Bedrock
    if not bedrock_client:
        st.warning("Failed to create Bedrock client.")
        return []

    try:
        # Fetch the list of foundation models using Bedrock client
        response = bedrock_client.list_foundation_models()
        models = response.get("models", [])
        if models:
            st.warning(f"Models retrieved: {models}")
            return models
        else:
            st.warning("No models available.")
            return []
    except Exception as e:
        st.warning(f"Error listing Bedrock models: {e}")
        return []


def get_bedrock_response(prompt):
    """
    Send the prompt to AWS Bedrock (Claude LLM) and return the response (no role assumption required).
    """
    st.warning("Attempting to send prompt to Bedrock.")
    bedrock_client = get_bedrock_client()
    if not bedrock_client:
        st.warning("Failed to create Bedrock client.")
        return {"answer": "Error: Bedrock client not available", "references": ""}

    try:
        response = bedrock_client.invoke_model(
            modelId="anthropic.claude-3-haiku",
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
