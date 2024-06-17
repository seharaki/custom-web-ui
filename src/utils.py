import datetime
import logging
import os

import boto3
import jwt
import urllib3
from streamlit_oauth import OAuth2Component

from urllib import parse, request

logger = logging.getLogger()

# Add a file handler to write logs to a file
file_handler = logging.FileHandler('/var/log/app.log')
file_handler.setLevel(logging.INFO)

# Configure logging
logging.basicConfig(level=logging.INFO, handlers=[
    logging.FileHandler('/var/log/app.log'),
    logging.StreamHandler()
])
logger = logging.getLogger(__name__)

# Read the configuration file
APPCONFIG_APP_NAME = os.environ["APPCONFIG_APP_NAME"]
APPCONFIG_ENV_NAME = os.environ["APPCONFIG_ENV_NAME"]
APPCONFIG_CONF_NAME = os.environ["APPCONFIG_CONF_NAME"]
AWS_CREDENTIALS = {}
AMAZON_Q_APP_ID = None
IAM_ROLE = None
REGION = None
IDC_APPLICATION_ID = None
OAUTH_CONFIG = {}

#DyanmoDb Configuration
#TODO Pull the REGION Dynamically
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

Q_TABLE_NAME = os.environ.get("Q_TABLE_NAME", "QBusinessAppVOA")
qbusiness_table = dynamodb.Table(Q_TABLE_NAME)

def retrieve_config_from_agent():
    """
    Retrieve the configuration from the agent
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
    Configure the OAuth2 component for Cognito
    """
    idp_config = urllib3.request(
        "GET",
            f"{OAUTH_CONFIG['CognitoDomain']}/.well-known/openid-configuration"
    ).json()

    authorize_url = idp_config["authorization_endpoint"]
    token_url = idp_config["token_endpoint"]
    refresh_token_url = idp_config["token_endpoint"]
    revoke_token_url = idp_config.get("revocation_endpoint")
    client_id = OAUTH_CONFIG["ClientId"]
    return OAuth2Component(
        client_id, None, authorize_url, token_url, refresh_token_url, revoke_token_url
    )

def refresh_iam_oidc_token(refresh_token):
    """
    Refresh the IAM OIDC token using the refresh token retrieved from Cognito
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
    Get the IAM OIDC token using the ID token retrieved from Cognito
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
    Assume IAM role with the IAM OIDC idToken
    """
    global AWS_CREDENTIALS
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
    AWS_CREDENTIALS = response["Credentials"]
    return response


# This method create the Q client
def get_qclient(idc_id_token: str):
    """
    Create the Q client using the identity-aware AWS Session.
    """
    if not AWS_CREDENTIALS or AWS_CREDENTIALS["Expiration"] < datetime.datetime.now(
        datetime.timezone.utc
    ):
        assume_role_with_token(idc_id_token)
    session = boto3.Session(
        aws_access_key_id=AWS_CREDENTIALS["AccessKeyId"],
        aws_secret_access_key=AWS_CREDENTIALS["SecretAccessKey"],
        aws_session_token=AWS_CREDENTIALS["SessionToken"],
    )
    amazon_q = session.client("qbusiness", REGION)
    return amazon_q


# This code invoke chat_sync api and format the response for UI
def get_queue_chain(
    prompt_input, conversation_id, parent_message_id, token
):
    """"
    This method is used to get the answer from the queue chain.
    """
    amazon_q = get_qclient(token)
    if conversation_id != "":
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

    if answer.get("sourceAttributions"):
        attributions = answer["sourceAttributions"]
        valid_attributions = []

        # Generate the answer references extracting citation number,
        # the document title, and if present, the document url
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

def store_feedback(user_email, conversation_id, parent_message_id, user_message, feedback):
    try:
        feedback_table.put_item(
            Item={
                'UserEmail': user_email,
                'ConversationId': conversation_id,
                'ParentMessageId': parent_message_id,
                'UserMessage': user_message,
                'Feedback': feedback,
                'Timestamp': datetime.datetime.utcnow().isoformat()
            }
        )
        logger.info("Feedback stored successfully")
    except Exception as e:
        logger.error(f"Error storing feedback: {e}")

def store_message_response(user_email, conversation_id, parent_message_id, user_message, response):
    try:
        feedback_table.put_item(
            Item={
                'UserEmail': user_email,
                'ConversationId': conversation_id,
                'ParentMessageId': parent_message_id,
                'UserMessage': user_message,
                'Response': response,
                'Timestamp': datetime.datetime.utcnow().isoformat()
            }
        )
        logger.info("Message and response stored successfully")
    except Exception as e:
        logger.error(f"Error storing message and response: {e}")
