import datetime
import logging
import os
import time
from decimal import Decimal

import boto3
import jwt
import streamlit as st
import urllib3
from streamlit_oauth import OAuth2Component
from collections import namedtuple
from datetime import datetime, timezone

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add a file handler to write logs to a file
file_handler = logging.FileHandler('/var/log/utils.log')
file_handler.setLevel(logging.INFO)

# Add the handlers to the logger
logger.addHandler(file_handler)

# DynamoDb Configuration
Q_TABLE_NAME = os.environ.get("Q_TABLE_NAME", "QBusinessAppVOA")

# Timezone
UTC = timezone.utc

# Read the configuration file
APPCONFIG_APP_NAME = os.environ["APPCONFIG_APP_NAME"]
APPCONFIG_ENV_NAME = os.environ["APPCONFIG_ENV_NAME"]
APPCONFIG_CONF_NAME = os.environ["APPCONFIG_CONF_NAME"]
AMAZON_Q_APP_ID = None
IAM_ROLE = None
REGION = "us-east-1"
IDC_APPLICATION_ID = None
OAUTH_CONFIG = {}
APP_VERSION = 1
Config = namedtuple('Config', ['IAM_ROLE', 'REGION', 'IDC_APPLICATION_ID', 'AMAZON_Q_APP_ID', 'OAUTH_CONFIG'])

def retrieve_config_from_agent():
    """
    Retrieve the configuration from the agent
    """
    config = urllib3.request(
        "GET",
        f"http://localhost:2772/applications/{APPCONFIG_APP_NAME}/environments/{APPCONFIG_ENV_NAME}/configurations/{APPCONFIG_CONF_NAME}",
    ).json()
    IAM_ROLE = config["IamRoleArn"]
    REGION = config["Region"]
    IDC_APPLICATION_ID = config["IdcApplicationArn"]
    AMAZON_Q_APP_ID = config["AmazonQAppId"]
    OAUTH_CONFIG = config["OAuthConfig"]
    return Config(IAM_ROLE, REGION, IDC_APPLICATION_ID, AMAZON_Q_APP_ID, OAUTH_CONFIG)

def configure_oauth_component(OAUTH_CONFIG: dict):
    """
    Configure the OAuth2 component
    """
    idp_config = urllib3.request(
        "GET",
            f"{OAUTH_CONFIG['Domain']}/.well-known/openid-configuration"
    ).json()

    authorize_url = idp_config["authorization_endpoint"]
    token_url = idp_config["token_endpoint"]
    refresh_token_url = idp_config["token_endpoint"]
    revoke_token_url = idp_config.get("revocation_endpoint")
    client_id = OAUTH_CONFIG["ClientId"]
    return OAuth2Component(
        client_id, None, authorize_url, token_url, refresh_token_url, revoke_token_url
    )

def get_iam_oidc_token(id_token, config: Config):
    """
    Get the IAM OIDC token using the ID token retrieved from Cognito
    """
    client = boto3.client("sso-oidc", region_name=config.REGION)
    response = client.create_token_with_iam(
        clientId=config.IDC_APPLICATION_ID,
        grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion=id_token,
    )
    return response

def assume_role_with_token(iam_token, config: Config):
    """
    Assume IAM role with the IAM OIDC idToken
    """
    decoded_token = jwt.decode(iam_token, options={"verify_signature": False})
    sts_client = boto3.client("sts", region_name=config.REGION)
    response = sts_client.assume_role(
        RoleArn=config.IAM_ROLE,
        RoleSessionName="qapp",
        ProvidedContexts=[
            {
                "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                "ContextAssertion": decoded_token["sts:identity_context"],
            }
        ],
    )
    st.session_state.aws_credentials = response["Credentials"]

# This method creates the Q client
def get_qclient(idc_id_token: str, config: Config):
    """
    Create the Q client using the identity-aware AWS Session.
    """
    if not st.session_state.aws_credentials:
        assume_role_with_token(idc_id_token, config)
    elif st.session_state.aws_credentials["Expiration"] < datetime.now(UTC):
        assume_role_with_token(idc_id_token, config)

    session = boto3.Session(
        aws_access_key_id=st.session_state.aws_credentials["AccessKeyId"],
        aws_secret_access_key=st.session_state.aws_credentials["SecretAccessKey"],
        aws_session_token=st.session_state.aws_credentials["SessionToken"],
    )
    if config.REGION == "" or config.REGION == None:
        st.warning("Setting Region")
        config.REGION = "us-east-1"
    st.warning(f"Current Region {config.REGION}")
    amazon_q = session.client("qbusiness", config.REGION)
    return amazon_q

# This code invokes chat_sync API and formats the response for UI
def get_queue_chain(
    prompt_input, conversation_id, parent_message_id, token, config: Config
):
    """
    This method is used to get the answer from the queue chain.
    """
    amazon_q = get_qclient(token, config)
    start_time = time.time()
    if conversation_id != "":
        answer = amazon_q.chat_sync(
            applicationId=config.AMAZON_Q_APP_ID,
            userMessage=prompt_input,
            conversationId=conversation_id,
            parentMessageId=parent_message_id,
        )
    else:
        answer = amazon_q.chat_sync(
            applicationId=config.AMAZON_Q_APP_ID, userMessage=prompt_input)

    end_time = time.time()
    duration = end_time - start_time
    st.warning(duration)

    system_message = answer.get("systemMessage", "")
    conversation_id = answer.get("conversationId", "")
    parent_message_id = answer.get("systemMessageId", "")
    result = {
        "answer": system_message,
        "conversationId": conversation_id,
        "parentMessageId": parent_message_id,
        "duration": Decimal(duration)  # Convert duration to Decimal
    }

    if answer.get("sourceAttributions"):
        attributions = answer["sourceAttributions"]
        valid_attributions = []

        # Generate the answer references extracting citation number,
        # the document title, and if present, the document URL
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

        concatenated_attributions = "\n\n".join(valid_attributions)
        result["references"] = concatenated_attributions

        # Process the citation numbers and insert them into the system message
        citations = {}
        for attr in answer["sourceAttributions"]:
            for segment in attr["textMessageSegments"]:
                citations[segment["endOffset"]] = attr["citationNumber"]
        offset_citations = sorted(citations.items(), key=lambda x: x[0])
        modified_message = ""
        prev_offset = 0

        for offset, citation_number in offset_citations:
            modified_message += (
                system_message[prev_offset:offset] + f"[{citation_number}]"
            )
            prev_offset = offset

        modified_message += system_message[prev_offset:]
        result["answer"] = modified_message

    return result

def store_feedback(user_email, conversation_id, parent_message_id, user_message, feedback, config: Config):
    try:
        dynamodb = boto3.resource('dynamodb', region_name=config.REGION)
        qbusiness_table = dynamodb.Table(Q_TABLE_NAME)
        qbusiness_table.put_item(
            Item={
                'UserId': user_email,
                'ConversationId': conversation_id,
                'ParentMessageId': parent_message_id,
                'UserMessage': user_message,
                'Feedback': feedback,
                'Timestamp': datetime.now(tz=UTC).isoformat()
            }
        )
        logger.info("Feedback stored successfully")
    except Exception as e:
        logger.error(f"Error storing feedback: {e}")

def store_message_response(user_email, conversation_id, parent_message_id, user_message, response, config: Config):
    try:
        dynamodb = boto3.resource('dynamodb', region_name=config.REGION)
        qbusiness_table = dynamodb.Table(Q_TABLE_NAME)
        qbusiness_table.put_item(
            Item={
                'UserId': user_email,
                'ConversationId': conversation_id,
                'ParentMessageId': parent_message_id,
                'UserMessage': user_message,
                'Response': response["answer"],
                'References': response.get("references", ""),
                'Duration': response["duration"],
                'Timestamp': datetime.now(tz=UTC).isoformat()
            }
        )
        logger.info("Message and response stored successfully")
    except Exception as e:
        logger.error(f"Error storing message and response: {e}")
