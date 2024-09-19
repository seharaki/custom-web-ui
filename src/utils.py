import json
import boto3
import jwt
import streamlit as st
from retrying import retry
from streamlit_oauth import OAuth2Component
import urllib3
import datetime

logger = logging.getLogger()

# Global Configuration
APPCONFIG_APP_NAME = os.environ["APPCONFIG_APP_NAME"]
APPCONFIG_ENV_NAME = os.environ["APPCONFIG_ENV_NAME"]
APPCONFIG_CONF_NAME = os.environ["APPCONFIG_CONF_NAME"]
IAM_ROLE = None
REGION = None
IDC_APPLICATION_ID = None
AMAZON_Q_APP_ID = None
OAUTH_CONFIG = {}

# Retrieve configuration from AppConfig
def retrieve_config_from_agent():
    global IAM_ROLE, REGION, OAUTH_CONFIG, IDC_APPLICATION_ID, AMAZON_Q_APP_ID
    st.warning("Attempting to retrieve configuration from the agent.")
    try:
        config = urllib3.PoolManager().request(
            "GET",
            f"http://localhost:2772/applications/{APPCONFIG_APP_NAME}/environments/{APPCONFIG_ENV_NAME}/configurations/{APPCONFIG_CONF_NAME}",
        ).data.decode('utf-8')
        config_json = json.loads(config)
        IAM_ROLE = config_json["IamRoleArn"]
        REGION = config_json["Region"]
        IDC_APPLICATION_ID = config_json["IdcApplicationArn"]
        AMAZON_Q_APP_ID = config_json["AmazonQAppId"]
        OAUTH_CONFIG = config_json["OAuthConfig"]
        st.session_state.region = REGION
        st.warning(f"Configuration retrieved successfully. IAM_ROLE: {IAM_ROLE}, REGION: {REGION}")
    except Exception as e:
        st.warning(f"Error retrieving configuration: {e}")

# OAuth component
def configure_oauth_component():
    try:
        cognito_domain = OAUTH_CONFIG["CognitoDomain"]
        authorize_url = f"https://{cognito_domain}/oauth2/authorize"
        token_url = f"https://{cognito_domain}/oauth2/token"
        client_id = OAUTH_CONFIG["ClientId"]
        return OAuth2Component(client_id, None, authorize_url, token_url)
    except Exception as e:
        st.warning(f"Error configuring OAuth2 component: {e}")
        return None

# Refresh IAM OIDC Token
def refresh_iam_oidc_token(refresh_token):
    st.warning("Attempting to refresh IAM OIDC token.")
    try:
        client = boto3.client("sso-oidc", region_name=st.session_state.region)
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

# Get IAM OIDC Token
def get_iam_oidc_token(id_token):
    st.warning("Attempting to get IAM OIDC token.")
    try:
        client = boto3.client("sso-oidc", region_name=st.session_state.region)
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

# Assume IAM Role for Q ChatSync
def assume_role_with_token(iam_token):
    st.warning("Attempting to assume role with IAM token.")
    try:
        decoded_token = jwt.decode(iam_token, options={"verify_signature": False})
        sts_client = boto3.client("sts", region_name=st.session_state.region)
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

# Get Q Business Client
def get_qclient(idc_id_token):
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
            return session.client("qbusiness", region_name=st.session_state.region)
        except Exception as e:
            st.warning(f"Error creating Amazon Q client: {e}")
            return None
    else:
        st.warning("Failed to obtain valid AWS credentials.")
        return None

# Get Queue Chain (Q ChatSync)
def get_queue_chain(prompt_input, conversation_id, parent_message_id, token):
    st.warning("Attempting to invoke Amazon Q chat_sync API.")
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

        st.warning(f"Amazon Q chat_sync API invoked successfully. Response: {result}")
        return result

    except Exception as e:
        st.warning(f"Error invoking Amazon Q chat_sync API: {e}")
        return None

# Get Bedrock Client
def get_bedrock_client(service="bedrock"):
    st.warning(f"Attempting to create Bedrock client for {service}.")
    session = boto3.Session(region_name=st.session_state.region)
    return session.client(service)

# List Available Bedrock Models
def list_available_bedrock_models():
    st.warning("Attempting to list available Bedrock models.")
    try:
        bedrock_client = get_bedrock_client(service="bedrock")
        response = bedrock_client.list_foundation_models()
        models = response.get("models", [])
        st.warning(f"Models retrieved: {models}")
        return models
    except Exception as e:
        st.warning(f"Error listing Bedrock models: {e}")
        return []

# Get Bedrock Response (Using Knowledge Base)
def get_bedrock_response(prompt, knowledge_base_id):
    st.warning(f"Attempting to send prompt to Bedrock Knowledge Base: {knowledge_base_id}.")
    try:
        bedrock_client = get_bedrock_client(service="bedrock-agent-runtime")
        response = bedrock_client.retrieve_and_generate(
            input={"text": prompt},
            retrieveAndGenerateConfiguration={
                "type": "KNOWLEDGE_BASE",
                "knowledgeBaseConfiguration": {
                    "knowledgeBaseId": knowledge_base_id,
                    "modelArn": f"arn:aws:bedrock:{st.session_state.region}::foundation-model/amazon.titan-embed-text-v1"
                }
            },
        )
        output_text = response["output"]["text"]
        st.warning(f"Bedrock response received: {output_text}")
        return {"answer": output_text}
    except Exception as e:
        st.warning(f"Error invoking Bedrock Knowledge Base: {e}")
        return {"answer": "Error: Failed to retrieve response from Bedrock Knowledge Base."}
