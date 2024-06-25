import logging
import os
 
import boto3
import jwt
import urllib3
from datetime import datetime, timezone
from collections import namedtuple
from streamlit_oauth import OAuth2Component
 
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
Config = namedtuple('Config', ['IAM_ROLE', 'REGION', 'IDC_APPLICATION_ID', 'AMAZON_Q_APP_ID', 'OAUTH_CONFIG'])
 
# Timezone
UTC = timezone.utc
 
# Retrieve Config from Agent
def retrieve_config_from_agent():
    """
    Retrieve the configuration from the agent
    """
    config = urllib3.request(
        "GET",
        f"http://localhost:2772/applications/{APPCONFIG_APP_NAME}/environments/{APPCONFIG_ENV_NAME}/configurations/{APPCONFIG_CONF_NAME}",
    ).json()
    logger.info(f"http://localhost:2772/applications/{APPCONFIG_APP_NAME}/environments/{APPCONFIG_ENV_NAME}/configurations/{APPCONFIG_CONF_NAME}")
    logger.info(f"The config in the method is {config}")
    IAM_ROLE = config["IamRoleArn"]
    REGION = config["Region"]
    IDC_APPLICATION_ID = config["IdcApplicationArn"]
    AMAZON_Q_APP_ID = config["AmazonQAppId"]
    OAUTH_CONFIG = config["OAuthConfig"]
    response = Config(IAM_ROLE, REGION, IDC_APPLICATION_ID, AMAZON_Q_APP_ID, OAUTH_CONFIG)
    return response
 
#DyanmoDb Configuration
Q_TABLE_NAME = os.environ.get("Q_TABLE_NAME", "QBusinessAppVOA")
 
def configure_oauth_component(OAUTH_CONFIG:dict):
    """
    Configure the OAuth2 component for Cognito
    """
    logger.info(f"The config in the oauth component is {OAUTH_CONFIG}")
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
 
def refresh_iam_oidc_token(refresh_token, config:Config):
    """
    Refresh the IAM OIDC token using the refresh token retrieved from Cognito
    """
    client = boto3.client("sso-oidc", region_name=config.REGION)
    response = client.create_token_with_iam(
        clientId=config.IDC_APPLICATION_ID,
        grantType="refresh_token",
        refreshToken=refresh_token,
    )
    return response
 
 
def get_iam_oidc_token(id_token, config:Config):
    """
    Get the IAM OIDC token using the ID token retrieved from Cognito
    """
    logger.info(f"Current id_token: {id_token}")
    logger.info(f"Current config: {config}")
    logger.info(f"Current IDC_APPLICATION_ID: {config.IDC_APPLICATION_ID}")
    client = boto3.client("sso-oidc", region_name=config.REGION)
    response = client.create_token_with_iam(
        clientId=config.IDC_APPLICATION_ID,
        grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion=id_token,
    )
    return response
 
 
def assume_role_with_token(iam_token, config:Config):
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
    return response
 
 
# This method create the Q client
def get_qclient(idc_id_token: str, config:Config):
    """
    Create the Q client using the identity-aware AWS Session.
    """
    if not AWS_CREDENTIALS or AWS_CREDENTIALS["Expiration"] < datetime.datetime.now(
        datetime.timezone.utc
    ):
        response = assume_role_with_token(idc_id_token, config)
        AWS_CREDENTIALS = response["Credentials"]
    session = boto3.Session(
        aws_access_key_id=AWS_CREDENTIALS["AccessKeyId"],
        aws_secret_access_key=AWS_CREDENTIALS["SecretAccessKey"],
        aws_session_token=AWS_CREDENTIALS["SessionToken"],
    )
    amazon_q = session.client("qbusiness", config.REGION)
    return amazon_q
 
 
# This code invoke chat_sync api and format the response for UI
def get_queue_chain(
    prompt_input, conversation_id, parent_message_id, token, config
):
    """"
    This method is used to get the answer from the queue chain.
    """
    amazon_q = get_qclient(token, config.REGION, config.IAM_ROLE)
    if conversation_id != "":
        answer = amazon_q.chat_sync(
            applicationId=config.AMAZON_Q_APP_ID,
            userMessage=prompt_input,
            conversationId=conversation_id,
            parentMessageId=parent_message_id,
        )
    else:
        answer = amazon_q.chat_sync(
            applicationId=config.AMAZON_Q_APP_ID, userMessage=prompt_input
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
 
def store_feedback(user_email, conversation_id, parent_message_id, user_message, feedback, config:Config):
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
 
def store_message_response(user_email, conversation_id, parent_message_id, user_message, response, config:Config):
    try:
        dynamodb = boto3.resource('dynamodb', region_name=config.REGION)
        qbusiness_table = dynamodb.Table(Q_TABLE_NAME)
        qbusiness_table.put_item(
            Item={
                'UserId': user_email,
                'ConversationId': conversation_id,
                'ParentMessageId': parent_message_id,
                'UserMessage': user_message,
                'Response': response,
                'Timestamp': datetime.now(tz=UTC).isoformat()
            }
        )
        logger.info("Message and response stored successfully")
    except Exception as e:
        logger.error(f"Error storing message and response: {e}")