from ast import Import
from logging.handlers import RotatingFileHandler
import urllib.parse
from flask import Flask, abort, jsonify, request, redirect, send_from_directory, stream_with_context, url_for, render_template, flash, session,Response
import requests
from forms import LoginForm  # Import the form class
from authlib.integrations.flask_client import OAuth
from flask_wtf import CSRFProtect
import bleach
import time
from mdos.mdos_sanitizer import PromptAnalyzer,prompt
from markupsafe import escape
from dateutil.relativedelta import relativedelta
import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import VARCHAR, DateTime, Column, ForeignKey, BigInteger, NVARCHAR, Integer, Table, desc, UniqueConstraint,create_engine, MetaData, Column, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship, sessionmaker, backref
from sqlalchemy.ext.declarative import declarative_base
from self_protection import protect, sanitize_input, getHash, encStandard, decStandard  
import openai
import logging
import anthropic
import uuid
from sensitive_information.sensitive_data_sanitizer import SensitiveDataSanitizer
from aishieldsemail import send_secure_email
import secrets
from prompt_injection_sanitizer.prompt_injection_sanitizer import Prompt_Injection_Sanitizer,pre_proecess_prompt,prompt_injection_score
from insecure_output_handling.insecure_output_handling import InsecureOutputSanitizer
#from overreliance.overreliance_data_sanitizer import OverrelianceDataSanitizer as ODS
import json
import netifaces as nif
import os
import security_config as sc
import pathlib
import textwrap
import google.generativeai as googlegenai
from google.api_core.client_options import ClientOptions
import stripe
import urllib
from markupsafe import Markup
from flask_wtf.csrf import CSRFError
from google.cloud import recaptchaenterprise_v1
from google.cloud.recaptchaenterprise_v1 import Assessment
from validate_email_address import validate_email


app = Flask(__name__)
#stripe_endpoint = str("success")
app.config['SECRET_KEY'] = str(decStandard(sc.SECRET_KEY))
app.config['SQLALCHEMY_DATABASE_URI'] = sc.SQLALCHEMY_DATABASE_URI
app.config['GOOGLE_CLIENT_ID'] = sc.GOOGLE_CLIENT_ID
app.config['GOOGLE_CLIENT_SECRET'] = sc.GOOGLE_CLIENT_SECRET
email_from = sc.EMAIL_FROM
smtpserver = sc.SMTP_SERVER
smtpport = sc.SMTP_PORT
smtpp = sc.SMTP_PASSWORD
smtpu = sc.SMTP_USER
smtp_server = str(decStandard(smtpserver))
smtp_port = str(decStandard(smtpport))
smtp_p = str(decStandard(smtpp))
smtp_u = str(decStandard(smtpu))
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
oauth = OAuth(app)
handler = RotatingFileHandler(sc.LOG_PATH, maxBytes=10000000, backupCount=5)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)
stripe.api_key = str(decStandard(sc.STRIPE_K))
# Connection URL
DATABASE_URI = sc.SQLALCHEMY_DATABASE_URI


# Using declarative_base
Base = declarative_base()

apis = [{"APIowner":"OpenAI","TextGen": {"Name":"ChatGPT","Models":[
               # {"Name":"GPT o1-Preview","details":{ "uri": "https://api.openai.com/v1/chat/completions","jsonv":"o1-preview"}},
                {"Name":"GPT 4o","details":{ "uri": "https://api.openai.com/v1/chat/completions","jsonv":"gpt-4o"}},
                {"Name":"GPT 4","details":{ "uri": "https://api.openai.com/v1/chat/completions","jsonv":"gpt-4"}},
                {"Name":"GPT 4 Turbo Preview","details":{ "uri": "https://api.openai.com/v1/chat/completions","jsonv":"gpt-4-turbo-preview" }},
                {"Name":"GPT 3.5 Turbo","details":{"uri":"https://api.openai.com/v1/chat/completions","jsonv": "gpt-3.5-turbo"}}
                ]}},
                {"APIowner":"Anthropic","TextGen": {"Name":"Claude","Models":[
                {"Name":"Sonnet June 20, 2024","details":{"uri": "https://api.anthropic.com/v1/messages","jsonv":"claude-3-5-sonnet-20240620"}},
                {"Name":"Opus February 29, 2024","details":{"uri": "https://api.anthropic.com/v1/messages","jsonv":"claude-3-opus-20240229"}},
                ]}},
                {"APIowner":"Google","TextGen": {"Name":"Gemini","Models":[
                {"Name":"Gemini 2.0 Flash","details":{"uri": "https://generativelanguage.googleapis.com/v2/{model=models/gemini-2.0-flash}:generateContent","jsonv":"gemini-2.0-flash-exp"}},
                {"Name":"Gemini 1.5 Pro","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.5-pro}:generateContent","jsonv":"gemini-1.5-pro"}},
                {"Name":"Gemini 1.5 Flash","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.5-flash}:generateContent","jsonv":"gemini-1.5-flash"}},
                {"Name":"Gemini 1.0 Pro","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.0-pro}:generateContent","jsonv":"gemini-1.0-pro"}}
                 ]}},
                {"APIowner":"Perplexity","TextGen": {"Name":"Perplexity.ai","Models":[
                {"Name":"Meta llama-3.1-large-chat","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.5-pro}:generateContent","jsonv":"llama-3.1-sonar-large-128k-chat"}},
                {"Name":"Meta llama-3.1-small-chat","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.5-flash}:generateContent","jsonv":"llama-3.1-sonar-small-128k-chat"}},
                {"Name":"Meta llama-3.1-large-online","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.5-pro}:generateContent","jsonv":"llama-3.1-sonar-large-128k-online"}},
                {"Name":"Meta llama-3.1-small-online","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.5-flash}:generateContent","jsonv":"llama-3.1-sonar-small-128k-online"}},
                {"Name":"Meta llama-3.1-70b-instruct","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.0-pro}:generateContent","jsonv":"llama-3.1-70b-instruct"}},
                {"Name":"Meta llama-3.1-8b-instruct","details":{"uri": "https://generativelanguage.googleapis.com/v1/{model=models/gemini-1.0-pro}:generateContent","jsonv":"llama-3.1-8b-instruct"}}
                 ]}}]
def check_email(email):
  try:
    is_valid = validate_email(email, verify=True)
    return is_valid
  except Exception as err:
    logging.error('An error occurred during email validation: %s', err)
    flash("An error occurred. Please try again.")
    return False
  
def create_recaptcha_assessment(
     token: str, recaptcha_action: str, user_ip_address: str, user_agent: str, ja3: str
    ) -> Assessment:
    """Create an assessment to analyze the risk of a UI action.
    Args:
        project_id: Your Google Cloud Project ID.
        recaptcha_key: The reCAPTCHA key associated with the site/app
        token: The generated token obtained from the client.
        recaptcha_action: Action name corresponding to the token.
    """

    client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()

    # Set the properties of the event to be tracked.
    event = recaptchaenterprise_v1.Event()
    event.site_key = sc.GOOGLE_Recaptcha_Key_ID
    event.token = token

    assessment = recaptchaenterprise_v1.Assessment()
    assessment.event = event

    project_name = f"projects/{sc.GOOGLE_Recaptcha_Project_ID}"

    # Build the assessment request.
    request = recaptchaenterprise_v1.CreateAssessmentRequest()
    request.assessment = assessment
    request.parent = project_name

    response = client.create_assessment(request)

    # Check if the token is valid.
    if not response.token_properties.valid:
        print(
            "The CreateAssessment call failed because the token was "
            + "invalid for the following reasons: "
            + str(response.token_properties.invalid_reason)
        )
        return

    # Check if the expected action was executed.
    if response.token_properties.action != recaptcha_action:
        print(
            "The action attribute in your reCAPTCHA tag does"
            + "not match the action you are expecting to score"
        )
        return
    else:
        # Get the risk score and the reason(s).
        # For more information on interpreting the assessment, see:
        # https://cloud.google.com/recaptcha-enterprise/docs/interpret-assessment
        for reason in response.risk_analysis.reasons:
            print(reason)
        print(
            "The reCAPTCHA score for this token is: "
            + str(response.risk_analysis.score)
        )
        # Get the assessment name (id). Use this to annotate the assessment.
        assessment_name = client.parse_assessment_path(response.name).get("assessment")
        print(f"Assessment name: {assessment_name}")
    return 1,response

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This API returns user details.
    client_kwargs={'scope': 'openid email profile'},
)

def app_context():
    app = Flask(__name__)
    #setup engine and session
    strAppKey = decStandard(sc.STR_APP_KEY)
    app.secret_key = strAppKey.encode(str="utf-8")
    csrf = CSRFProtect(app)
    with app.app_context():
        yield


#Base = declarative_base()

user_prompt_api_model = Table(
    "user_prompt_api_model",
    db.metadata,
    db.Column("user_id", BigInteger,ForeignKey("users.id")),
    db.Column("prompt_id", BigInteger, ForeignKey("inputPrompt.id")),
    db.Column("preproc_prompt_id",BigInteger,ForeignKey("preprocInputPrompt.id")),
    db.Column("apiresponse_id",BigInteger,ForeignKey("apiResponse.id")),
    db.Column("aishields_report_id",BigInteger,ForeignKey("aiShieldsReport.id")),
    db.Column("postproc_response_id",BigInteger,ForeignKey("postprocResponse.id")),
    db.Column("GenApi_id",BigInteger,ForeignKey("GenApi.id"))
)

user_codes_users = Table(
    "user_codes_users",
    db.metadata,
    db.Column("user_id", BigInteger,ForeignKey("users.id")),
    db.Column("user_codes_id", BigInteger,ForeignKey("user_codes.id")),
)
user_api = Table(
    "user_api",
    db.metadata,
    db.Column("user_id", BigInteger,ForeignKey("users.id")),
    db.Column("genapi_id", BigInteger, ForeignKey("GenApi.id")),
)

user_api_cred = Table(
    "user_api_cred",
    db.metadata,
    db.Column("user_id", BigInteger,ForeignKey("users.id")),
    db.Column("api_id",BigInteger,ForeignKey("GenApi.id")),
    db.Column("cred_id",BigInteger,ForeignKey("cred.id")),
    db.Column("created_date",DateTime)
)

requests_client = Table(
 "requests_client",
    db.metadata,
    db.Column("request_id", BigInteger,ForeignKey("requests.id")),
    db.Column("client_id", BigInteger, ForeignKey("clients.id")),
   
)
class User_Optin(db.Model):
    __tablename__ = "user_optin"
    id = db.Column(BigInteger, primary_key=True)
    user_id=db.Column(BigInteger,ForeignKey("users.id"))
    user_optin=db.Column(Integer,default=0)
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    updated_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))

class User_Subscriptions(db.Model):
    __tablename__ = "user_subscriptions"
    id = db.Column(BigInteger, primary_key=True)
    user_id=db.Column(BigInteger,ForeignKey("users.id"))
    subscription = db.Column(VARCHAR)
    active = db.Column(Integer,default=1)

class Clients(db.Model):
    __tablename__ = "clients"
    id = db.Column(BigInteger, primary_key=True)
    IPaddress = db.Column(NVARCHAR)
    MacAddress = db.Column(NVARCHAR)
    create_date = db.Column(DateTime,unique=False, default=datetime.datetime.now(datetime.timezone.utc))
    requests = relationship("RequestLog", secondary=requests_client)

class RequestLog(db.Model):
    __tablename__ = "requests"
    id = db.Column(Integer, primary_key=True)
    client_id = db.Column(Integer, nullable=False)  # Assuming client ID is a string
    client_ip = db.Column(NVARCHAR, nullable=False)  # Assuming client ID is a string
    url = db.Column(NVARCHAR)
    request_type = db.Column(NVARCHAR)
    Headers = db.Column(NVARCHAR)  # Using Text instead of NVARCHAR for compatibility
    Body = db.Column(NVARCHAR)
    create_date = db.Column(DateTime, nullable=False, default=datetime.datetime.now)

    # def __init__(self, client_id,client_ip request_type, headers, body, url):
    #     self.client_ip = client_ip
    #     self.client_id = client_id
    #     self.request_type = request_type
    #     self.Headers = headers
    #     self.Body = body
    #     self.url = url

    @staticmethod
    def get_request_count(client_ip):
        # Calculate the datetime 10 minutes ago
        ten_minutes_ago = datetime.datetime.now() - datetime.timedelta(minutes=10)
        
        # Filter requests based on client_id and creation date
        return RequestLog.query.filter_by(client_ip=client_ip).filter(RequestLog.create_date >= ten_minutes_ago).count()

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(BigInteger, primary_key=True)
    session_id = db.Column(NVARCHAR)
    subscribed = db.Column(Integer, default=0)
    provider = db.Column(NVARCHAR, default='AiShields')
    username = db.Column(NVARCHAR)
    first_name = db.Column(NVARCHAR)
    last_name = db.Column(NVARCHAR)
    passphrase = db.Column(NVARCHAR)
    email = db.Column(NVARCHAR)
    user_verified = db.Column(Integer,default=0)
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    updated_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    session_start = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    session_end = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc).__add__(datetime.timedelta(days=0, seconds=0, microseconds=0, milliseconds=0, minutes=20, hours=0, weeks=0)))
    inputPrompts = relationship("InputPrompt",secondary=user_prompt_api_model)
    preprocPrompts = relationship("PreProcInputPrompt", secondary=user_prompt_api_model)
    apiResponses = relationship("ApiResponse",secondary=user_prompt_api_model)
    postProcResponses = relationship("PostProcResponse",secondary=user_prompt_api_model)
    aiShieldsReports = relationship("AiShieldsReport",secondary=user_prompt_api_model)
    genApis = relationship(
        "GenApi", secondary=user_api, back_populates="users"
    )
    user_codes = relationship(
        "UserCode", secondary=user_codes_users, back_populates="users",
    )
    
class UserCode(db.Model):
    __tablename__ = "user_codes"
    id = db.Column(BigInteger, primary_key=True)
    user_id = db.Column(BigInteger,ForeignKey("users.id"))
    email = db.Column(NVARCHAR)
    code = db.Column(NVARCHAR)
    created_date = db.Column(DateTime,unique=False, default=datetime.datetime.now(datetime.timezone.utc))
    users = relationship("User", back_populates="user_codes")

class Credential(db.Model):
    __tablename__ = "cred"
    id = db.Column(BigInteger, primary_key=True)
    user_id = db.Column(BigInteger,ForeignKey("users.id"))
    api_id = db.Column(BigInteger,ForeignKey("GenApi.id"))
    username = db.Column(NVARCHAR)
    email = db.Column(NVARCHAR)
    token = db.Column(NVARCHAR, unique=False, nullable=True)
    jwt = db.Column(NVARCHAR, unique=False, nullable=True)
    header = db.Column(NVARCHAR, unique=False, nullable=True)
    formfield = db.Column(NVARCHAR, unique=False, nullable=True)
    created_date = db.Column(DateTime,unique=False, default=datetime.datetime.now(datetime.timezone.utc))
    updated_date = db.Column(DateTime, unique=False, nullable=True)

class GenApi(db.Model):
    __tablename__ = "GenApi"
    id = db.Column(BigInteger, primary_key=True)
    api_owner = db.Column(NVARCHAR, unique=False, nullable=False)
    api_name =  db.Column(NVARCHAR, unique=False, nullable=False)
    uri = db.Column(NVARCHAR, unique=False, nullable=False)
    headers = db.Column(NVARCHAR, unique=False, nullable=True)
    formfields = db.Column(NVARCHAR, unique=False, nullable=True)
    model = db.Column(NVARCHAR, unique=True, nullable=False)
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    updated_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    inputPrompts = relationship("InputPrompt", secondary=user_prompt_api_model)
    preprocPrompts = relationship("PreProcInputPrompt", secondary=user_prompt_api_model)
    apiResponses = relationship("ApiResponse",secondary=user_prompt_api_model)
    postProcResponses = relationship("PostProcResponse",secondary=user_prompt_api_model)
    aiShieldsReports = relationship("AiShieldsReport",secondary=user_prompt_api_model)
    users = relationship(
        "User", secondary=user_api, back_populates="genApis"
    )
    
# class User(db.Model):
#     id = db.db.Column(BigInteger, primary_key=True)
#     username = db.db.Column(NVARCHAR, unique=True, nullable=False)
#     email = db.db.Column(NVARCHAR, unique=True, nullable=False)
    
class InputPrompt(db.Model):
    __tablename__ = "inputPrompt"
    id = db.Column(BigInteger, primary_key=True)
    user_id = db.Column(BigInteger,ForeignKey("users.id"))
    cred_id = db.Column(BigInteger, ForeignKey("cred.id"))
    username = db.Column(NVARCHAR)
    email = db.Column(NVARCHAR)
    api_id = db.Column(BigInteger,ForeignKey("GenApi.id"))
    api = db.Column(NVARCHAR)
    internalPromptID = db.Column(NVARCHAR,unique=True)
    inputPrompt = db.Column(NVARCHAR)
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    updated_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
  
    
class PreProcInputPrompt(db.Model):
    __tablename__ = "preprocInputPrompt"
    id = db.Column(BigInteger, primary_key=True)
    user_id = db.Column(BigInteger,ForeignKey("users.id"))
    username = db.Column(NVARCHAR)
    email = db.Column(NVARCHAR)
    api_id = db.Column(BigInteger,ForeignKey("GenApi.id"))
    api = db.Column(NVARCHAR,unique=False,nullable=False)
    internalPromptID = db.Column(NVARCHAR,nullable=False)
    rawInputPrompt_id = db.Column(BigInteger,ForeignKey("inputPrompt.id"),nullable=False)
    inputPrompt = db.Column(NVARCHAR,unique=False,nullable=False)
    preProcInputPrompt = db.Column(NVARCHAR,unique=False,nullable=False)
    SensitiveDataSanitizerReport = db.Column(NVARCHAR,unique=False,nullable=True)
    PromptInjectionReport = db.Column(NVARCHAR,unique=False,nullable=True)    
    OverrelianceReport = db.Column(NVARCHAR,unique=False,nullable=True)
    OverrelianceKeyphraseData = db.Column(NVARCHAR,unique=False,nullable=True)
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    updated_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))

 
class ApiResponse(db.Model):
    __tablename__ = "apiResponse"
    id = db.Column(BigInteger, primary_key=True)
    user_id = db.Column(BigInteger,ForeignKey("users.id"))
    username = db.Column(NVARCHAR)
    email = db.Column(NVARCHAR)
    internalPromptID = db.Column(NVARCHAR,unique=False,nullable=False)
    preProcPrompt_id = db.Column(BigInteger,ForeignKey("preprocInputPrompt.id"))
    rawInputPrompt_id = db.Column(BigInteger,ForeignKey("inputPrompt.id"))
    externalPromptID = db.Column(NVARCHAR,unique=False,nullable=False)
    api_id = db.Column(BigInteger,ForeignKey("GenApi.id"))
    api = db.Column(NVARCHAR) 
    rawoutput = db.Column(NVARCHAR)
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
      
class PostProcResponse(db.Model):
    __tablename__ = "postprocResponse"
    id = db.Column(BigInteger, primary_key=True)
    rawInputPrompt_id = db.Column(BigInteger, ForeignKey("inputPrompt.id"))
    inputPromptID = db.Column(NVARCHAR,unique=False,nullable=False)
    preProcPrompt_id = db.Column(BigInteger, ForeignKey("preprocInputPrompt.id"))
    externalPromptID = db.Column(NVARCHAR,unique=False,nullable=False)
    user_id = db.Column(BigInteger,ForeignKey("users.id"))
    username = db.Column(NVARCHAR)
    email = db.Column(NVARCHAR)
    api_id = db.Column(BigInteger,ForeignKey("GenApi.id"))
    api = db.Column(NVARCHAR,unique=False,nullable=False)
    rawResponseID = db.Column(BigInteger,ForeignKey("apiResponse.id"))
    rawOutputResponse = db.Column(NVARCHAR,unique=False,nullable=False)
    InsecureOutputHandlingReport = db.Column(NVARCHAR,unique=False,nullable=False)
    postProcOutputResponse = db.Column(NVARCHAR,unique=False,nullable=False)    
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    
class AiShieldsReport(db.Model):
    __tablename__ = "aiShieldsReport"
    id = db.Column(BigInteger, primary_key=True)
    rawInputPrompt_id = db.Column(BigInteger, ForeignKey("inputPrompt.id"))
    preProcPrompt_id = db.Column(BigInteger, ForeignKey("preprocInputPrompt.id"))
    rawResponse_id = db.Column(BigInteger, ForeignKey("apiResponse.id"))
    postProcResponse_id = db.Column(BigInteger, ForeignKey("postprocResponse.id"))
    internalPromptID = db.Column(NVARCHAR,unique=False,nullable=False)
    externalPromptID = db.Column(NVARCHAR,unique=False,nullable=True)
    user_id = db.Column(BigInteger,ForeignKey("users.id"))
    username = db.Column(NVARCHAR, unique=False, nullable=False)
    email = db.Column(NVARCHAR, unique=False, nullable=False)
    api_id = db.Column(BigInteger,ForeignKey("GenApi.id"))
    api = db.Column(NVARCHAR,unique=False,nullable=False)
    SensitiveDataSanitizerReport = db.Column(NVARCHAR,unique=False,nullable=True)
    PromptInjectionReport = db.Column(NVARCHAR,unique=False,nullable=True)    
    OverrelianceReport = db.Column(NVARCHAR,unique=False,nullable=True)
    InsecureOutputReportHandling = db.Column(NVARCHAR,unique=False,nullable=True)     
    MDOSreport = db.Column(NVARCHAR,unique=False,nullable=True)   
    created_date = db.Column(DateTime,default=datetime.datetime.now(datetime.timezone.utc))
    updated_date = db.Column(DateTime)

class User_Info():
    api:str
    email:str
    token:str
    username:str
    inputprompt:str
    internalID = str(uuid.uuid4())
    lstApi:str
    strApi:str
    strModel:str
    userid:int
    sensitiveData:bool
    overrelianceData:bool
    messages = list[str]()
    googlemessages = list[dict]()
    openaimessages = list[dict]()
    perplexitymessages = list[dict]()
    anthropicmessages = list[dict]()
    googleusermessages = list[str]()
    googleassistantmessages = list[str]()                
                
          
def mac_for_ip(ip):
    'Returns a list of MACs for interfaces that have given IP, returns None if not found'
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except IndexError: #ignore ifaces that dont have MAC or IP
            if_mac = if_ip = None
        except KeyError:
            if_mac = if_ip = None
        if if_ip == ip:
            return if_mac
    return None

@app.template_filter('urlencode')
def urlencode_filter(s):
    if type(s) == 'Markup':
      s = s.unescape()
    s = s.encode('utf8')
    s = urllib.parse.urlencode({'prefilled_email': s})
    return Markup(s)

@app.before_request
def before_request():
    try:
        public_routes = ['login','c','pay','messages', 'create_checkout_session','subscribe','subscribed','cancel','newaccount', 'forgot', 'verifyemail', 'static','reset', 'success','webhook','index','home']
        if 'logged_in' not in session and request.endpoint not in public_routes:
            if request.url.startswith("https://checkout.stripe.com"):
               #stripe_endpoint = request.endpoint
               #public_routes += request.endpoint
              return redirect(request.url)
            if request.url.lower().startswith("https://chat.aishields.org/webhook"):
              return redirect(request.url)
            return redirect(url_for('login'))
        if request.url.startswith("https://checkout.stripe.com"):
            #stripe_endpoint = request.endpoint
            #public_routes += request.endpoint
            return redirect(request.url)
        if request.url.lower().startswith("https://chat.aishields.org/webhook"):
            #stripe_endpoint = request.endpoint
            #public_routes += request.endpoint
            return redirect(request.url)
        # Save the request data for MDOS protection
        macAddress = mac_for_ip(request.headers.get('X-Forwarded-For', request.remote_addr))
        if macAddress is None:
            macAddress = "?"
        client_info = Clients(
            IPaddress=request.headers.get('X-Forwarded-For', request.remote_addr),
            MacAddress=macAddress
        )
        db.session.add(client_info)
        db.session.commit()
        db.session.flush()
        request_data = RequestLog(
            client_id=client_info.id, 
            client_ip=client_info.IPaddress, 
            request_type=request.method,
            Headers=repr(dict(request.headers)),
            Body=request.data.decode('utf-8'),
            url=request.url
        )
        db.session.add(request_data)
        db.session.commit()

        # MDOS (Model Denial of Service entrypoint)
        # James Yu can add code here to handle MDOS protection
        client_id = request.remote_addr
        request_count = RequestLog.get_request_count(client_id)
        
        if request_count >= 500:  # Adjust the limit as needed
            flash('Too many requests, please try again later', 'danger')
            print(request_count)
            abort(429)  # Too Many Requests status code
    except Exception as err:
        logging.error('An error occurred during login: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('index.html', form=LoginForm())

@app.route('/subscribe',methods=['GET'])
def subscribe():
    try:
        if request.method == 'GET':
            if request.form.get('email') is not None:
                return render_template('subscribe.html',email=request.form.get('email'),noemail=False)
            else:
                return render_template('subscribe.html',noemail=True)
            
    except Exception as err:
        logging.error('An error occured during subscribe request: ' + str(err))
        flash("An error occurred." + str(err) +" Please try again.")
        return render_template('subscribe.html')
    
@app.route('/subscribed', methods=['GET', 'POST'])
def subscribed():
    try:
        if request.method == 'GET':
            session = stripe.checkout.Session.retrieve(request.args.get('session_id'))
            if session:
                customer = stripe.Customer.retrieve(session.customer)
                form = LoginForm(email=customer.email)
                return render_template('login.html', form=form)
            return render_template('login.html')
        flash("Your account has been created, please login")
        return render_template('login.html')
    except Exception as err:
        logging.error('An error occured during  request: ' + str(err))
        flash("An error occurred." + str(err) +" Please try again.")
        return render_template('subscribe.html')
    
@app.route('/cancel',methods=['GET'])
def cancel():
    try:
        if request.method == 'GET':
            return render_template('cancel.html',email=request.form.get('email'))
            
    except Exception as err:
        logging.error('An error occured during cancel page load request: ' + str(err))
        flash("An error occurred." + str(err) +" Please try again.")
        return render_template('subscribe.html')

@app.route('/create_checkout_session', methods=['POST'])
def create_checkout_session():
    try:
        #prices = stripe.Price.list(
        #     lookup_keys=[request.form['lookup_key']],
        #     expand=['data.product']
        # )
        strEmail = ""
        if request.form.get('email2') is not None:
            strEmail = str(request.form.get("email2")).lower()
        #elif request.form.get("email") is not None:
         #   strEmail = str(request.form.get("email")).lower()
        logging.error('\n\n\n' + strEmail + '\n\n\n')
        usercode = UserCode()
        usercode.user_id = 0
        usercode.email = strEmail
        usercode.code = str(uuid.uuid4())
        db.session.add(usercode)
        db.session.commit()
        db.session.flush(objects=[usercode])   
        # user = (
        #         db.session.query(User)
        #         .filter(User.email == strEmail.lower(),User.user_verified == 1)
        #         .first()
        #     )
        if strEmail is not None :
            checkout_session = stripe.checkout.Session.create(
                line_items=[
                    {
                        'price': 'price_1QLsumHaRvggpAUsjGPY5Dc6', #'price_1PPjO8DLTE0Q14oGUFYIbzNb',
                        'quantity': 1
                    },
                ],
                metadata={"email":str(strEmail),'code':str(usercode.code)},
                customer_email=str(strEmail),
                mode="subscription",
                subscription_data={
                "trial_period_days": 14,
                "trial_settings": {"end_behavior": {"missing_payment_method": "cancel"}},},
                payment_method_collection="always",
                success_url='https://chat.aishields.org/subscribed?session_id={CHECKOUT_SESSION_ID}',
                cancel_url='https://chat.aishields.org/cancel.html',
            )
            logging.error('\n\n\n' + checkout_session.url + '\n\n\n')
            return redirect(checkout_session.url, code=303)
        flash("Please subscribe to our free trial")
        return render_template('subscribe.html')
    except Exception as e:
        logging.error(e)
        flash(e)
        return "Server error", 500

@app.route('/create_portal_session', methods=['POST'])
def create_portal_session():
    # For demonstration purposes, we're using the Checkout session to retrieve the customer ID.
    # Typically this is stored alongside the authenticated user in your database.
    checkout_session_id = request.form.get('session_id')
    customer_email = request.form.get('email')
    checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)
    current_user = (
                db.session.query(User)
                .filter(User.email == customer_email,User.user_verified == 1, User.subscribed==1)
                .first()
            )
    current_user.session_id = checkout_session_id
    current_user.session_start = datetime.datetime.now(datetime.timezone.utc)
    current_user.session_end = datetime.datetime.now(datetime.timezone.utc).__add__(datetime.timedelta(datetime.timedelta(days=0, seconds=0, microseconds=0, milliseconds=0, minutes=5, hours=0, weeks=0)))
    db.commit(current_user)
    db.flush(objects=[current_user])
    
    # This is the URL to which the customer will be redirected after they are
    # done managing their billing with the portal.
    return_url = "https://chat.aishields.org/profile"

    portalSession = stripe.billing_portal.Session.create(
        customer=checkout_session.customer,
        return_url=return_url,
    )
    return redirect(portalSession.url, code=303)

@csrf.exempt
@app.route('/webhook', methods=['POST'])
def webhook():
    # Replace this endpoint secret with your endpoint's unique secret
    # If you are testing with the CLI, find the secret by running 'stripe listen'
    # If you are using an endpoint defined with the API or dashboard, look in your webhook settings
    # at https://dashboard.stripe.com/webhooks
    webhook_secret = str(decStandard(sc.STRIPE_SignK))
    request_data = json.loads(request.data)

    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')
        try:
            event = stripe.Webhook.construct_event(
                payload=request.data, sig_header=signature, secret=webhook_secret)
            data = event['data']
        except Exception as e:
            return e
        # Get the type of webhook event sent - used to check the status of PaymentIntents.
        event_type = event['type']
    else:
        data = request_data['data']
        event_type = request_data['type']
    data_object = data['object']

    logging.error('event ' + event_type)

    if event_type == 'checkout.session.completed':
        logging.error('🔔 Payment succeeded!')
        if data_object is not None:
            email = data_object["customer_email"]
            subscription_id = data_object['subscription']
            user = (db.session.query(User)
                    .filter(User.email==email,User.user_verified==1)
                    .first())
            user.subscribed = 1
            db.session.add(user)
            db.session.commit()
            db.session.flush(objects=[user])
            user_subscription = User_Subscriptions()
            user_subscription.active = 1
            user_subscription.subscription = subscription_id
            user_subscription.user_id = user.id
            db.session.add(user_subscription)
            db.session.commit()
            db.session.flush(objects=[user_subscription])
            
    elif event_type == 'customer.subscription.trial_will_end':
        logging.error('Subscription trial will end')
    elif event_type == 'customer.subscription.created':
        logging.error('Subscription created %s', event.id)
    elif event_type == 'customer.subscription.updated':
        logging.error('Subscription created %s', event.id)
    elif event_type == 'customer.subscription.deleted':
        # handle subscription canceled automatically based
        # upon your subscription settings. Or if the user cancels it.
        stripe_customer_id = data_object["customer"]
        customer = stripe.Customer.retrieve(id=stripe_customer_id)
        email = customer.email
        user = (db.session.query(User)
                .filter(User.email==email,User.user_verified==1)
                .first())
        user_subscription = (db.session.query(User_Subscriptions)
                             .filter(User_Subscriptions.user_id ==user.id)
                             .first())
        if user_subscription is None:
          user_subscription = User_Subscriptions()
          user_subscription.active = 0
          user_subscription.user_id = user.id
          user_subscription.subscription = "NA"
        user_subscription.active = 0
        user.subscribed = 0
        db.session.add(user)
        db.session.add(user_subscription)
        db.session.commit()
        db.session.flush(objects=[user,user_subscription])
        logging.error('Subscription canceled: %s', event.id)
    elif event['type'] == 'account.updated':
      account = event['data']['object']
    elif event['type'] == 'account.external_account.created':
      external_account = event['data']['object']
    elif event['type'] == 'account.external_account.deleted':
      external_account = event['data']['object']
    elif event['type'] == 'account.external_account.updated':
      external_account = event['data']['object']
    elif event['type'] == 'balance.available':
      balance = event['data']['object']
    elif event['type'] == 'billing_portal.configuration.created':
      configuration = event['data']['object']
    elif event['type'] == 'billing_portal.configuration.updated':
      configuration = event['data']['object']
    elif event['type'] == 'billing_portal.session.created':
      session = event['data']['object']
    elif event['type'] == 'capability.updated':
      capability = event['data']['object']
    elif event['type'] == 'cash_balance.funds_available':
      cash_balance = event['data']['object']
    elif event['type'] == 'charge.captured':
      charge = event['data']['object']
    elif event['type'] == 'charge.expired':
      charge = event['data']['object']
    elif event['type'] == 'charge.failed':
      charge = event['data']['object']
    elif event['type'] == 'charge.pending':
      charge = event['data']['object']
    elif event['type'] == 'charge.refunded':
      charge = event['data']['object']
    elif event['type'] == 'charge.succeeded':
      charge = event['data']['object']
    elif event['type'] == 'charge.updated':
      charge = event['data']['object']
    elif event['type'] == 'charge.dispute.closed':
      dispute = event['data']['object']
    elif event['type'] == 'charge.dispute.created':
      dispute = event['data']['object']
    elif event['type'] == 'charge.dispute.funds_reinstated':
      dispute = event['data']['object']
    elif event['type'] == 'charge.dispute.funds_withdrawn':
      dispute = event['data']['object']
    elif event['type'] == 'charge.dispute.updated':
      dispute = event['data']['object']
    elif event['type'] == 'charge.refund.updated':
      refund = event['data']['object']
    elif event['type'] == 'checkout.session.async_payment_failed':
      session = event['data']['object']
    elif event['type'] == 'checkout.session.async_payment_succeeded':
      session = event['data']['object']
    elif event['type'] == 'checkout.session.completed':
      session = event['data']['object']
    elif event['type'] == 'checkout.session.expired':
      session = event['data']['object']
    elif event['type'] == 'climate.order.canceled':
      order = event['data']['object']
    elif event['type'] == 'climate.order.created':
      order = event['data']['object']
    elif event['type'] == 'climate.order.delayed':
      order = event['data']['object']
    elif event['type'] == 'climate.order.delivered':
      order = event['data']['object']
    elif event['type'] == 'climate.order.product_substituted':
      order = event['data']['object']
    elif event['type'] == 'climate.product.created':
      product = event['data']['object']
    elif event['type'] == 'climate.product.pricing_updated':
      product = event['data']['object']
    elif event['type'] == 'coupon.created':
      coupon = event['data']['object']
    elif event['type'] == 'coupon.deleted':
      coupon = event['data']['object']
    elif event['type'] == 'coupon.updated':
      coupon = event['data']['object']
    elif event['type'] == 'credit_note.created':
      credit_note = event['data']['object']
    elif event['type'] == 'credit_note.updated':
      credit_note = event['data']['object']
    elif event['type'] == 'credit_note.voided':
      credit_note = event['data']['object']
    elif event['type'] == 'customer.created':
      customer = event['data']['object']
    elif event['type'] == 'customer.deleted':
      customer = event['data']['object']
    elif event['type'] == 'customer.updated':
      customer = event['data']['object']
    elif event['type'] == 'customer.discount.created':
      discount = event['data']['object']
    elif event['type'] == 'customer.discount.deleted':
      discount = event['data']['object']
    elif event['type'] == 'customer.discount.updated':
      discount = event['data']['object']
    elif event['type'] == 'customer.source.created':
      source = event['data']['object']
    elif event['type'] == 'customer.source.deleted':
      source = event['data']['object']
    elif event['type'] == 'customer.source.expiring':
      source = event['data']['object']
    elif event['type'] == 'customer.source.updated':
      source = event['data']['object']
    elif event['type'] == 'customer.subscription.created':
      subscription = event['data']['object']
    elif event['type'] == 'customer.subscription.deleted':
      subscription = event['data']['object']
    elif event['type'] == 'customer.subscription.paused':
      subscription = event['data']['object']
    elif event['type'] == 'customer.subscription.pending_update_applied':
      subscription = event['data']['object']
    elif event['type'] == 'customer.subscription.pending_update_expired':
      subscription = event['data']['object']
    elif event['type'] == 'customer.subscription.resumed':
      subscription = event['data']['object']
    elif event['type'] == 'customer.subscription.trial_will_end':
      subscription = event['data']['object']
    elif event['type'] == 'customer.subscription.updated':
      subscription = event['data']['object']
    elif event['type'] == 'customer.tax_id.created':
      tax_id = event['data']['object']
    elif event['type'] == 'customer.tax_id.deleted':
      tax_id = event['data']['object']
    elif event['type'] == 'customer.tax_id.updated':
      tax_id = event['data']['object']
    elif event['type'] == 'customer_cash_balance_transaction.created':
      customer_cash_balance_transaction = event['data']['object']
    elif event['type'] == 'entitlements.active_entitlement_summary.updated':
      active_entitlement_summary = event['data']['object']
    elif event['type'] == 'file.created':
      file = event['data']['object']
    elif event['type'] == 'financial_connections.account.created':
      account = event['data']['object']
    elif event['type'] == 'financial_connections.account.deactivated':
      account = event['data']['object']
    elif event['type'] == 'financial_connections.account.disconnected':
      account = event['data']['object']
    elif event['type'] == 'financial_connections.account.reactivated':
      account = event['data']['object']
    elif event['type'] == 'financial_connections.account.refreshed_balance':
      account = event['data']['object']
    elif event['type'] == 'financial_connections.account.refreshed_ownership':
      account = event['data']['object']
    elif event['type'] == 'financial_connections.account.refreshed_transactions':
      account = event['data']['object']
    elif event['type'] == 'identity.verification_session.canceled':
      verification_session = event['data']['object']
    elif event['type'] == 'identity.verification_session.created':
      verification_session = event['data']['object']
    elif event['type'] == 'identity.verification_session.processing':
      verification_session = event['data']['object']
    elif event['type'] == 'identity.verification_session.requires_input':
      verification_session = event['data']['object']
    elif event['type'] == 'identity.verification_session.verified':
      verification_session = event['data']['object']
    elif event['type'] == 'invoice.created':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.deleted':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.finalization_failed':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.finalized':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.marked_uncollectible':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.overdue':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.paid':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.payment_action_required':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.payment_failed':
      #email customer with link to payment portal: <a href="https://billing.stripe.com/p/login/8wM8yA8Mp6Rt7qo7ss">Manage Subscription</a>
      #change subscription status to 2
      email = data_object["customer_email"]
      user = (db.session.query(User)
              .filter(User.email == email,User.subscribed == 1,User.user_verified)
              .first())
      to_email = user.email
      from_email = smtp_u
      s_server = smtp_server
      s_port = smtp_port
      s_p = smtp_p
      m_subj = "Payment failed for subscription to AiShields"
      m_message = "Dear " + user.first_name + ", \n\n Please update your payment method to keep your AiShields subscription active using this link: https://billing.stripe.com/p/login/8wM8yA8Mp6Rt7qo7ss?prefilled_email=" + str(email).replace('@','%40') + " \n\n Thank you, \n\n Support@AiShields.org"
      send_secure_email(to_email,from_email,s_server,s_port,from_email,s_p,m_subj,m_message)
      user.subscribed = 0
      user_subscription = (db.session.query(User_Subscriptions)
                           .filter(User_Subscriptions.user_id == user.id).first())
      user_subscription.active = 2 
      db.session.add(user)
      db.session.add(user_subscription)
      db.session.commit()
      db.session.flush(objects=[user,user_subscription])         
      invoice = event['data']['object']
    elif event['type'] == 'invoice.payment_succeeded':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.sent':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.upcoming':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.updated':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.voided':
      invoice = event['data']['object']
    elif event['type'] == 'invoice.will_be_due':
      invoice = event['data']['object']
    elif event['type'] == 'invoiceitem.created':
      invoiceitem = event['data']['object']
    elif event['type'] == 'invoiceitem.deleted':
      invoiceitem = event['data']['object']
    elif event['type'] == 'issuing_authorization.created':
      issuing_authorization = event['data']['object']
    elif event['type'] == 'issuing_authorization.updated':
      issuing_authorization = event['data']['object']
    elif event['type'] == 'issuing_card.created':
      issuing_card = event['data']['object']
    elif event['type'] == 'issuing_card.updated':
      issuing_card = event['data']['object']
    elif event['type'] == 'issuing_cardholder.created':
      issuing_cardholder = event['data']['object']
    elif event['type'] == 'issuing_cardholder.updated':
      issuing_cardholder = event['data']['object']
    elif event['type'] == 'issuing_dispute.closed':
      issuing_dispute = event['data']['object']
    elif event['type'] == 'issuing_dispute.created':
      issuing_dispute = event['data']['object']
    elif event['type'] == 'issuing_dispute.funds_reinstated':
      issuing_dispute = event['data']['object']
    elif event['type'] == 'issuing_dispute.submitted':
      issuing_dispute = event['data']['object']
    elif event['type'] == 'issuing_dispute.updated':
      issuing_dispute = event['data']['object']
    elif event['type'] == 'issuing_personalization_design.activated':
      issuing_personalization_design = event['data']['object']
    elif event['type'] == 'issuing_personalization_design.deactivated':
      issuing_personalization_design = event['data']['object']
    elif event['type'] == 'issuing_personalization_design.rejected':
      issuing_personalization_design = event['data']['object']
    elif event['type'] == 'issuing_personalization_design.updated':
      issuing_personalization_design = event['data']['object']
    elif event['type'] == 'issuing_token.created':
      issuing_token = event['data']['object']
    elif event['type'] == 'issuing_token.updated':
      issuing_token = event['data']['object']
    elif event['type'] == 'issuing_transaction.created':
      issuing_transaction = event['data']['object']
    elif event['type'] == 'issuing_transaction.updated':
      issuing_transaction = event['data']['object']
    elif event['type'] == 'mandate.updated':
      mandate = event['data']['object']
    elif event['type'] == 'payment_intent.amount_capturable_updated':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_intent.canceled':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_intent.created':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_intent.partially_funded':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_intent.payment_failed':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_intent.processing':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_intent.requires_action':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_intent.succeeded':
      payment_intent = event['data']['object']
    elif event['type'] == 'payment_link.created':
      payment_link = event['data']['object']
    elif event['type'] == 'payment_link.updated':
      payment_link = event['data']['object']
    elif event['type'] == 'payment_method.attached':
      payment_method = event['data']['object']
    elif event['type'] == 'payment_method.automatically_updated':
      payment_method = event['data']['object']
    elif event['type'] == 'payment_method.detached':
      payment_method = event['data']['object']
    elif event['type'] == 'payment_method.updated':
      payment_method = event['data']['object']
    elif event['type'] == 'payout.canceled':
      payout = event['data']['object']
    elif event['type'] == 'payout.created':
      payout = event['data']['object']
    elif event['type'] == 'payout.failed':
      payout = event['data']['object']
    elif event['type'] == 'payout.paid':
      payout = event['data']['object']
    elif event['type'] == 'payout.reconciliation_completed':
      payout = event['data']['object']
    elif event['type'] == 'payout.updated':
      payout = event['data']['object']
    elif event['type'] == 'person.created':
      person = event['data']['object']
    elif event['type'] == 'person.deleted':
      person = event['data']['object']
    elif event['type'] == 'person.updated':
      person = event['data']['object']
    elif event['type'] == 'plan.created':
      plan = event['data']['object']
    elif event['type'] == 'plan.deleted':
      plan = event['data']['object']
    elif event['type'] == 'plan.updated':
      plan = event['data']['object']
    elif event['type'] == 'price.created':
      price = event['data']['object']
    elif event['type'] == 'price.deleted':
      price = event['data']['object']
    elif event['type'] == 'price.updated':
      price = event['data']['object']
    elif event['type'] == 'product.created':
      product = event['data']['object']
    elif event['type'] == 'product.deleted':
      product = event['data']['object']
    elif event['type'] == 'product.updated':
      product = event['data']['object']
    elif event['type'] == 'promotion_code.created':
      promotion_code = event['data']['object']
    elif event['type'] == 'promotion_code.updated':
      promotion_code = event['data']['object']
    elif event['type'] == 'quote.accepted':
      quote = event['data']['object']
    elif event['type'] == 'quote.canceled':
      quote = event['data']['object']
    elif event['type'] == 'quote.created':
      quote = event['data']['object']
    elif event['type'] == 'quote.finalized':
      quote = event['data']['object']
    elif event['type'] == 'quote.will_expire':
      quote = event['data']['object']
    elif event['type'] == 'radar.early_fraud_warning.created':
      early_fraud_warning = event['data']['object']
    elif event['type'] == 'radar.early_fraud_warning.updated':
      early_fraud_warning = event['data']['object']
    elif event['type'] == 'refund.created':
      refund = event['data']['object']
    elif event['type'] == 'refund.updated':
      refund = event['data']['object']
    elif event['type'] == 'reporting.report_run.failed':
      report_run = event['data']['object']
    elif event['type'] == 'reporting.report_run.succeeded':
      report_run = event['data']['object']
    elif event['type'] == 'review.closed':
      review = event['data']['object']
    elif event['type'] == 'review.opened':
      review = event['data']['object']
    elif event['type'] == 'setup_intent.canceled':
      setup_intent = event['data']['object']
    elif event['type'] == 'setup_intent.created':
      setup_intent = event['data']['object']
    elif event['type'] == 'setup_intent.requires_action':
      setup_intent = event['data']['object']
    elif event['type'] == 'setup_intent.setup_failed':
      setup_intent = event['data']['object']
    elif event['type'] == 'setup_intent.succeeded':
      setup_intent = event['data']['object']
    elif event['type'] == 'sigma.scheduled_query_run.created':
      scheduled_query_run = event['data']['object']
    elif event['type'] == 'source.canceled':
      source = event['data']['object']
    elif event['type'] == 'source.chargeable':
      source = event['data']['object']
    elif event['type'] == 'source.failed':
      source = event['data']['object']
    elif event['type'] == 'source.mandate_notification':
      source = event['data']['object']
    elif event['type'] == 'source.refund_attributes_required':
      source = event['data']['object']
    elif event['type'] == 'source.transaction.created':
      transaction = event['data']['object']
    elif event['type'] == 'source.transaction.updated':
      transaction = event['data']['object']
    elif event['type'] == 'subscription_schedule.aborted':
      subscription_schedule = event['data']['object']
    elif event['type'] == 'subscription_schedule.canceled':
      subscription_schedule = event['data']['object']
    elif event['type'] == 'subscription_schedule.completed':
      subscription_schedule = event['data']['object']
    elif event['type'] == 'subscription_schedule.created':
      subscription_schedule = event['data']['object']
    elif event['type'] == 'subscription_schedule.expiring':
      subscription_schedule = event['data']['object']
    elif event['type'] == 'subscription_schedule.released':
      subscription_schedule = event['data']['object']
    elif event['type'] == 'subscription_schedule.updated':
      subscription_schedule = event['data']['object']
    elif event['type'] == 'tax.settings.updated':
      settings = event['data']['object']
    elif event['type'] == 'tax_rate.created':
      tax_rate = event['data']['object']
    elif event['type'] == 'tax_rate.updated':
      tax_rate = event['data']['object']
    elif event['type'] == 'terminal.reader.action_failed':
      reader = event['data']['object']
    elif event['type'] == 'terminal.reader.action_succeeded':
      reader = event['data']['object']
    elif event['type'] == 'test_helpers.test_clock.advancing':
      test_clock = event['data']['object']
    elif event['type'] == 'test_helpers.test_clock.created':
      test_clock = event['data']['object']
    elif event['type'] == 'test_helpers.test_clock.deleted':
      test_clock = event['data']['object']
    elif event['type'] == 'test_helpers.test_clock.internal_failure':
      test_clock = event['data']['object']
    elif event['type'] == 'test_helpers.test_clock.ready':
      test_clock = event['data']['object']
    elif event['type'] == 'topup.canceled':
      topup = event['data']['object']
    elif event['type'] == 'topup.created':
      topup = event['data']['object']
    elif event['type'] == 'topup.failed':
      topup = event['data']['object']
    elif event['type'] == 'topup.reversed':
      topup = event['data']['object']
    elif event['type'] == 'topup.succeeded':
      topup = event['data']['object']
    elif event['type'] == 'transfer.created':
      transfer = event['data']['object']
    elif event['type'] == 'transfer.reversed':
      transfer = event['data']['object']
    elif event['type'] == 'transfer.updated':
      transfer = event['data']['object']
    # ... handle other event types
    else:
      logging.error('Unhandled event type {}'.format(event['type']))
 
    return jsonify({'status': 'success'})


@app.route('/',methods=['GET','POST'])
def home():
    try:
        return render_template('index.html')
    except Exception as err:
        logging.error('An error occurred during home request: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('index.html')

@app.route('/index', methods=['GET', 'POST'])
def index():
    try:
        #if request.method == 'POST':
          #email = request.form.get('email')
          #if email is not None:
           # email = str(email).lower().strip(" ")
           #user = (
        #             db.session.query(User)
        #             .filter(User.email == str(request.form.get("email")).lower(),User.user_verified == 1)
        #             .first()
        #            ) 
        #     if (user is not None and user.user_verified > 0):
        #       form = LoginForm(email=str(user.email),passphrase='')
        #       return render_template('login.html',form=form)
        #     else:
        #       return render_template('newaccount.html', email=email)
        #   else:
        #     flash("Please enter a valid email address.")
        # else:
      return render_template('index.html')
    except Exception as err:
        logging.error('An error occurred in index request: %s', err)
        flash("An error occurred. Please try again. " +str(err))
        return render_template('index.html')

@app.route('/verifyemail',methods=['GET', 'POST'])
def verifyemail():
    try:
        if request.method == 'GET':
            return render_template('verifyemail.html', email=request.form.get(key='email'))
        if request.method == 'POST':
            # check recaptcha and for valid email:
            recaptcha_response = request.form.get('g-recaptcha-response')
            payload = {'secret': sc.GOOGLE_Recaptcha_Secret_Key, 'response': recaptcha_response}
            response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
            result = response.json()
            recaptchaSuccess = False
            if result.get('success'):
              recaptchaSuccess = True
            else:
              recaptchaSuccess = False
            if recaptchaSuccess == False:
              flash("reCaptcha Response failed. Try again")
              return render_template('verifyemail.html', email=request.form.get("email"))
            
            user_entered_code = str(request.form.get(key='passphrase'))
            usercodes = (db.session.query(UserCode).all)
            user_stored_code = (db.session.query(UserCode).filter(UserCode.email == str(request.form.get(key="email")).lower()).order_by(desc(UserCode.id)).first()) 
            user_code = str(user_stored_code.code)
            if user_code is not None:
                if user_code == user_entered_code:
                    user = (
                        db.session.query(User)
                        .filter(User.email == str(request.form["email"]).lower())
                        .order_by(desc(User.id)).first()
                    )
                    user.user_verified = 1
                    db.session.add(user)
                    db.session.commit()
                    db.session.flush(objects=[user])
                    userName = str(user.first_name + " " + user.last_name)
                    return render_template('subscribe.html', email=request.form.get("email"))
                else:
                    flash("Code did not match, please try entering the code again")
                    return render_template('verifyemail.html', email=request.form.get("email"))
            flash("Please enter the code from your email")
            return render_template('verifyemail.html', email=request.form.get("email"))
        return render_template('verifyemail.html', email=request.form.get("email"))
    except Exception as err:
        logging.error('An error occurred during verify login request: %s',str(err))
        flash("An error occurred. Please try again: " + str(err))
        return render_template('index.html', form=LoginForm())  
 
@app.route('/reset',methods=['GET','POST'])
def reset():
    try:
        if request.method == 'GET':
            strCode = request.args.get("code") #request.query_string.decode('utf-8').split(str('='))[1]
            return render_template('reset.html',code=strCode)
        if request.method == 'POST':
            # check recaptcha and for valid email:
            recaptcha_response = request.form.get('g-recaptcha-response')
            payload = {'secret': sc.GOOGLE_Recaptcha_Secret_Key, 'response': recaptcha_response}
            response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
            result = response.json()
            recaptchaSuccess = False
            if result.get('success'):
              recaptchaSuccess = True
            else:
              recaptchaSuccess = False
            if recaptchaSuccess == False:
              flash("reCaptcha failed. Try again")
              return render_template('reset.html', code=request.form.get("code"))
            
            code = str(request.form.get("code"))
            usercode = (
                db.session.query(UserCode)
                .filter(UserCode.code == code)
                .one_or_none()
            )
            if usercode is not None:
                user = (db.session.query(User).filter(User.id == usercode.user_id,User.user_verified == 1)
                        .first())
                user.passphrase = str(getHash(request.form.get(key="passphrase")))
                db.session.add(user)
                db.session.commit()
                db.session.flush(objects=[user])
                to_email = user.email
                from_email = smtp_u
                s_server = smtp_server
                s_port = smtp_port
                s_p = smtp_p
                m_subj = "Your password was just reset for AiShields.org"
                m_message = "Dear " + user.first_name + ", \n\n Your password was just changed for AiShields. \n\nPlease contact us via email at support@aishields.org if you did not just change your password. \n\n Thank you, \n\n Support@AiShields.org"
                send_secure_email(to_email,from_email,s_server,s_port,from_email,s_p,m_subj,m_message)
                flash("Your password has been changed")
                #now delete the code
                db.session.delete(usercode)
                db.session.commit()
                db.session.flush(objects=[usercode])
                #strCode = request.query_string.decode('utf-8').split('=')[1]
                form = LoginForm(email=user.email)
                return render_template('login.html',form=form)
            else:
                flash("Something went wrong please try again.")
                #strCode = request.query_string.decode('utf-8').split('=')[1]
                return render_template('reset.html',code=code)
    except Exception as err:
        logging.error('An error occurred during during reset request: %s', err)
        flash("An error occurred." + str(err) +" Please try again.")
        #strCode = request.query_string.decode('utf-8').split(str('='))[1]
        return render_template('reset.html')

@app.route('/forgot',methods=['GET','POST'])
def forgot():
    try:
        if request.method == 'GET':
            return render_template('forgot.html')
        if request.method == 'POST':
            if request.form.get('email') is not None:
              email = str(request.form.get("email")).lower()
              # check recaptcha and for valid email:
              recaptcha_response = request.form.get('g-recaptcha-response')
              payload = {'secret': sc.GOOGLE_Recaptcha_Secret_Key, 'response': recaptcha_response}
              response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
              result = response.json()
              recaptchaSuccess = False
              if result.get('success'):
                recaptchaSuccess = True
              else:
                recaptchaSuccess = False
              if recaptchaSuccess == False:
                flash("reCaptcha Response failed. Try again")
                return render_template('forgot.html')
              
              user = (
                  db.session.query(User)
                  .filter(User.email == email,User.user_verified == 1)
                  .first()
              )
              if user is not None:
                  if user.user_verified == 1:
                      strCode = str(uuid.uuid4())
                      code = UserCode(user_id=user.id,email=user.email,code=strCode)
                      db.session.add(code)
                      db.session.commit()
                      db.session.flush(objects=[code])
                      to_email = user.email
                      from_email = smtp_u
                      s_server = smtp_server
                      s_port = smtp_port
                      s_p = smtp_p
                      m_subj = "Reset instructions for AiShields.org"
                      m_message = "Dear " + user.first_name + ", \n\n Please click this link: <a href='https://chat.aishields.org/reset?code=" + strCode +"' or paste it into your browser address bar to change your password. \n\nThis link will expire in 20 minutes. \n\n Thank you, \n\n Support@AiShields.org"
                      send_secure_email(to_email,from_email,s_server,s_port,from_email,s_p,m_subj,m_message)
                      flash("An email was sent with a link to reset your password.")
                      return render_template('forgot.html')
                  
              else:
                flash("We could not find a verified account in our system with the email you entered")
                flash("Please create a new account and complete the email verification process")
                return render_template('newaccount.html', email=email)
            else:
              flash("Please enter your email address")
              return render_template('forgot.html')
    except Exception as err:
        logging.error('An error occured during forgot request: ' + str(err))
        flash("An error occurred." + str(err) +" Please try again.")
        return render_template('forgot.html')
    
             
@app.route('/newaccount',methods=['GET','POST'])
def newaccount():
    try:
        if request.method == 'GET':
          #sessionid = request.args.get('session_id')
          #checkoutsession = stripe.checkout.Session.retrieve(sessionid,)
          #email = checkoutsession.customer_email
         # user = (db.session.query(User).filter(User.subscribed == 1,User.email == email).first())
          #if user:
          return render_template('newaccount.html')
          # else:
          #   flash("Please Subscribe to Register a New Account")
          #   return render_template('subscribe.html')
        if request.method == 'POST':
            hp_field = request.form.get('hp_field')
            if hp_field:
                 # The honeypot field was filled, which likely indicates a bot.
                logging.error(msg="Bot detected! Ignoring submission.")
                return render_template('index.html')
            email = (
                db.session.query(User)
                .filter(User.email == str(request.form.get("email")).lower(),User.user_verified == 1)
                .one_or_none()
            )
            # check recaptcha and for valid email:
            recaptcha_response = request.form.get('g-recaptcha-response')
            payload = {'secret': sc.GOOGLE_Recaptcha_Secret_Key, 'response': recaptcha_response}
            response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
            result = response.json()
            recaptchaSuccess = False
            if result.get('success'):
              recaptchaSuccess = True
            else:
              recaptchaSuccess = False
            if recaptchaSuccess == False:
              flash("reCaptcha Response failed. Try again")
              return render_template('newaccount.html', email=request.form.get("email"),firstname=request.form.get("firstname"),lastname=request.form.get("lastname"))
            if email is not None:
                if email.user_verified == 1:
                    if email.subscribed == 1:
                      flash("Email is registered and you are subscribed, please login")
                      loginFrm = LoginForm(email=email.email)
                      return render_template('login.html',form=loginFrm)
                    else:
                      flash("Email is not subscribed please subscribe")
                      return render_template('subscribe.html',email=email.email)
            #bmonth = str(int(request.form["bmonth"]))
            #bday = str(int(request.form["bday"]))
            #byear = str(int(request.form["byear"]))
            #birthdate = datetime.date(int(byear),int(bmonth),int(bday))
            #yearstoadd = 18
            #currentdate = datetime.datetime.today()
            #difference_in_years = relativedelta(currentdate, birthdate).years 
                else:
                  emailValid = False
                  if check_email(email):
                    emailValid = True
                  if emailValid == False:
                    flash("Please enter a valid email address.")
                    return render_template('newaccount.html', email=request.form.get("email"),firstname=request.form.get("firstname"),lastname=request.form.get("lastname"))
          
                  firstname = sanitize_input(str(request.form["firstname"]).rstrip(' ').lstrip(' '))
                  lastname = sanitize_input(str(request.form["lastname"]).rstrip(' ').lstrip(' '))
                  username = str(firstname).capitalize() + " " + str(lastname).capitalize()
                  user = User(username=str(username),first_name=str(firstname),last_name=str(lastname),email=str(request.form["email"]).lower(),passphrase=getHash(request.form['passphrase']),user_verified=0,created_date=datetime.datetime.now(datetime.timezone.utc))
                  db.session.add(user)
                  db.session.commit()
                  db.session.flush(objects=[user])
                  strCode = ""
                  for i in range(6):
                    strCode += str(secrets.randbelow(10))
                  code = UserCode(user_id=user.id,email=user.email,code=strCode)
                  db.session.add(code)
                  db.session.commit()
                  db.session.flush(objects=[code])
                  to_email = user.email
                  from_email = smtp_u
                  s_server = smtp_server
                  s_port = smtp_port
                  s_p = smtp_p
                  m_subj = "Please verify your email for AiShields.org"
                  m_message = "Dear " + firstname + ", \n\n Please enter the following code: " + strCode + " in the email verification form. \n\n Thank you, \n\n Support@AiShields.org"
                  send_secure_email(to_email,from_email,s_server,s_port,from_email,s_p,m_subj,m_message)
                  return render_template('verifyemail.html',apis=apis, email=user.email)
            else:
              firstname = sanitize_input(str(request.form["firstname"]).rstrip(' ').lstrip(' '))
              lastname = sanitize_input(str(request.form["lastname"]).rstrip(' ').lstrip(' '))
              username = str(firstname).capitalize() + " " + str(lastname).capitalize()
              user = User(username=str(username),first_name=str(firstname),last_name=str(lastname),email=str(request.form["email"]).lower(),passphrase=getHash(request.form['passphrase']),user_verified=0,created_date=datetime.datetime.now(datetime.timezone.utc))
              db.session.add(user)
              db.session.commit()
              db.session.flush(objects=[user])
              strCode = ""
              for i in range(6):
                strCode += str(secrets.randbelow(10))
              code = UserCode(user_id=user.id,email=user.email,code=strCode)
              db.session.add(code)
              db.session.commit()
              db.session.flush(objects=[code])
              to_email = user.email
              from_email = smtp_u
              s_server = smtp_server
              s_port = smtp_port
              s_p = smtp_p
              m_subj = "Please verify your email for AiShields.org"
              m_message = "Dear " + firstname + ", \n\n Please enter the following code: " + strCode + " in the email verification form. \n\n Thank you, \n\n Support@AiShields.org"
              send_secure_email(to_email,from_email,s_server,s_port,from_email,s_p,m_subj,m_message)
              flash("An email was sent to your: " + to_email + ". Please check your junk or spam folder and add support@aishields.org to your address book")
              return render_template('verifyemail.html',apis=apis, email=user.email)
    except Exception as err:
        logging.error('An error occurred during newaccount request: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('login.html', form=LoginForm())

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/reportuser', methods=['GET', 'POST'])
def reportuser():
    try:
        #aishields_add_user()
        if request.method == 'GET':
           #aishields_add_user()
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            
            if not session.get('role') == "admrole":
              error_response = {"message": "Not logged in the appropriate role, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired, or you are not in the appropriate role to access this page")
              return render_template('login.html', form=LoginForm())
            if session.get('logged_in'):
              users = db.session.query(User).all()
              # #inputps = db.session.query(InputPrompt).filter(InputPrompt.email == 'patrick@gratitech.com')
              # inputpdict = {"prmpts":[InputPrompt]}
              # currentprmpts = [{}]
              # email = session['email']
              # user_id = session['user_id']
              # currentusers = [{}]
              # userdict = {"users":[User]}
              for user in users:
                email = user.email
                user_id = user.id
                first_name = user.first_name
                last_name = user.last_name
                username = user.username
                user_verified = user.user_verified
                user_subscribed = user.subscribed
                user_created = user.created_date
                if user_verified == 0:
                  if user_subscribed == 0:
                    db.session.delete(user)
                    db.session.commit()
                    db.session.flush(objects=[user])
                #userdict.append(user)
                # optinto = False
                # if user:
                #       user_optin = db.session.query(User_Optin).filter(User_Optin.user_id == user.id).order_by(desc(User_Optin.created_date)).first()
                #       optinto = False
                #       if user_optin:
                #         if user_optin.user_optin == 1:
                #           optinto = True
                #           optout = False
                #         else:
                #           optout = True
                #           optinto = False
                # current = {'id':user_id,'email':email,'first':first_name,'last':last_name,'username':username,'verified':user_verified,'subscribed':user_subscribed,'created':user_created,'optin':optinto}
                # currentusers.append(current)
                # flash('There are ' + str(len(currentusers))+ " verified and subscribed")
              return render_template('reportuser.html')#,users=currentusers,prmpts=currentprmpts,email=user.email)
        if request.method == 'POST':
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            # email = session['email']
            # user_id = session['user_id']
            # #email = request.form['email_hidden'].lower()
            # optin = 'no'
            # if request.form['options']:
            #   optin = str(request.form['options']).lower()
            # user = db.session.query(User).filter(User.email == email, User.user_verified == 1,User.id == user_id).one_or_none()
            # #return render_template('profile.html', email=user.email, firstname=user.first_name, lastname=user.last_name,optinto=user_optin)
        flash("Something went wrong. Please try again later.")
        return render_template('login.html', form=LoginForm())
    except Exception as err:
        logging.error('An error occurred during profile request: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('index.html', form=LoginForm())


@app.route('/rptuser', methods=['GET', 'POST'])
def rptuser():
    try:
        #aishields_add_user()
        if request.method == 'GET':
           #aishields_add_user()
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            
            if not session.get('role') == "admrole":
              error_response = {"message": "Not logged in the appropriate role, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired, or you are not in the appropriate role to access this page")
              return render_template('login.html', form=LoginForm())
            users = db.session.query(User).all()
            #inputps = db.session.query(InputPrompt).filter(InputPrompt.email == 'patrick@gratitech.com')
            inputpdict = {"prmpts":[InputPrompt]}
            currentprmpts = [{}]
            email = session['email']
            user_id = session['user_id']
            currentusers = [{}]
            userdict = {"users":[User]}
            for user in users:
              email = user.email
              user_id = user.id
              first_name = user.first_name
              last_name = user.last_name
              username = user.username
              user_verified = user.user_verified
              user_subscribed = user.subscribed
              user_created = user.created_date
              if user_id >= 43:
                if email == 'philrechani@gmail.com':
                  db.session.delete(user)
                  db.session.commit()
                  db.session.flush(objects=[user])
              #userdict.append(user)
              optinto = False
              if user:
                    user_optin = db.session.query(User_Optin).filter(User_Optin.user_id == user.id).order_by(desc(User_Optin.created_date)).first()
                    optinto = False
                    if user_optin:
                      if user_optin.user_optin == 1:
                        optinto = True
                        optout = False
                      else:
                        optout = True
                        optinto = False
              current = {'id':user_id,'email':email,'first':first_name,'last':last_name,'username':username,'verified':user_verified,'subscribed':user_subscribed,'created':user_created,'optin':optinto}
              currentusers.append(current)
              flash('There are ' + str(len(currentusers))+ " verified and subscribed")
            return render_template('rptuser.html',users=currentusers,prmpts=currentprmpts,email=user.email)
        if request.method == 'POST':
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            email = session['email']
            user_id = session['user_id']
            #email = request.form['email_hidden'].lower()
            optin = 'no'
            if request.form['options']:
              optin = str(request.form['options']).lower()
            user = db.session.query(User).filter(User.email == email, User.user_verified == 1,User.id == user_id).one_or_none()
            return render_template('profile.html', email=user.email, firstname=user.first_name, lastname=user.last_name,optinto=user_optin)
        flash("Something went wrong. Please try again later.")
        return render_template('login.html', email=email)
    except Exception as err:
        logging.error('An error occurred during profile request: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('index.html', form=LoginForm())


@app.route('/admuser', methods=['GET', 'POST'])
def admuser():
    try:
        #aishields_add_user()
        if request.method == 'GET':
           #aishields_add_user()
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            
            if not session.get('role') == "admrole":
              error_response = {"message": "Not logged in the appropriate role, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired, or you are not in the appropriate role to access this page")
              return render_template('login.html', form=LoginForm())
            users = db.session.query(User).all()
            inputps = db.session.query(InputPrompt).filter(InputPrompt.email == 'patrick@gratitech.com')
            inputpdict = {"prmpts":[InputPrompt]}
            currentprmpts = [{}]
            email = session['email']
            user_id = session['user_id']
            currentusers = [{}]
            for prmpt in inputps:
              #<td>ID</td><td>User</td><td>Prompt</td><td>API</td><td>Email</td><td>Created</td>
              #<tr><td>{{inputp.id}}</td><td>{{inputp.user}}</td><td>{{inputp.prompt}}</td><td>{{inputp.api}}</td><td>{{inputp.email}}</td><td>{{inputp.created}}</td></td>
              id = prmpt.internalPromptID
              user = prmpt.user_id
              prompt = prmpt.inputPrompt
              api = prmpt.api
              email = prmpt.email
              created = prmpt.created_date
              currentp = {'id':id,'user':user,'prompt':prompt,'api':api,'email':email,'created':created}
              currentprmpts.append(currentp) 
            userdict = {"users":[User]}
            for user in users:
              email = user.email
              user_id = user.id
              first_name = user.first_name
              last_name = user.last_name
              username = user.username
              user_verified = user.user_verified
              user_subscribed = user.subscribed
              user_created = user.created_date
              #userdict.append(user)
              optinto = False
              if user:
                    user_optin = db.session.query(User_Optin).filter(User_Optin.user_id == user.id).order_by(desc(User_Optin.created_date)).first()
                    optinto = False
                    if user_optin:
                      if user_optin.user_optin == 1:
                        optinto = True
                        optout = False
                      else:
                        optout = True
                        optinto = False
              current = {'id':user_id,'email':email,'first':first_name,'last':last_name,'username':username,'verified':user_verified,'subscribed':user_subscribed,'created':user_created,'optin':optinto}
              currentusers.append(current)
            return render_template('admuser.html',users=currentusers,prmpts=currentprmpts,email=user.email)
        if request.method == 'POST':
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            email = session['email']
            user_id = session['user_id']
            #email = request.form['email_hidden'].lower()
            optin = 'no'
            if request.form['options']:
              optin = str(request.form['options']).lower()
            user = db.session.query(User).filter(User.email == email, User.user_verified == 1,User.id == user_id).one_or_none()
            # if user:
            #     user_optin = False
            #     user_optout = True
            #     firstname = sanitize_input(request.form["firstname"].strip())
            #     lastname = sanitize_input(request.form["lastname"].strip())
            #     user.first_name = firstname
            #     user.last_name = lastname
            #     #user.passphrase = getHash(request.form['passphrase'])
            #     db.session.add(user)
            #     db.session.commit()
            #     db.session.flush(objects=[user])
            #     if optin:
            #       useroptin = User_Optin()
            #       useroptin.user_id = user.id
            #       if optin == 'yes':
            #          useroptin.user_optin = 1
            #          user_optin = True
            #          user_optout = False
            #       else:
            #          useroptin.user_optin = 0
            #          user_optin = False
            #          user_optout = True
            #       useroptin.created_date = datetime.datetime.utcnow()
            #       useroptin.updated_date = datetime.datetime.utcnow()
            #       db.session.add(useroptin)
            #       db.session.commit()
            #       db.session.flush(objects=[useroptin])
            #     flash("Profile updated successfully")
            return render_template('profile.html', email=user.email, firstname=user.first_name, lastname=user.last_name,optinto=user_optin)
        flash("Something went wrong. Please try again later.")
        return render_template('login.html', email=email)
    except Exception as err:
        logging.error('An error occurred during profile request: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('index.html', form=LoginForm())


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    try:
        #aishields_add_user()
        #aishields_add_model()
        if request.method == 'GET':
            aishields_add_user()
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            

            email = session['email']
            user_id = session['user_id']
            if email:
                user = db.session.query(User).filter(User.email == email, User.user_verified==1,User.id == user_id).one_or_none()
                if user:
                    user_optin = db.session.query(User_Optin).filter(User_Optin.user_id == user.id).order_by(desc(User_Optin.created_date)).first()
                    if user_optin:
                      if user_optin.user_optin == 1:
                        optinto = True
                        optout = False
                      else:
                        optout = True
                        optinto = False
                      return render_template('profile.html', email=user.email, firstname=user.first_name, lastname=user.last_name,optinto=optinto,optout=optout)
                    else:
                      return render_template('profile.html', email=user.email, firstname=user.first_name, lastname=user.last_name,optinto=False,optout=True)
            return render_template('login.html')
        if request.method == 'POST':
            if not session.get('logged_in'):
              error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
              flash("Please Login again, your session expired")
              return render_template('login.html', form=LoginForm())
            # check recaptcha and for valid email:
            recaptcha_response = request.form.get('g-recaptcha-response')
            payload = {'secret': sc.GOOGLE_Recaptcha_Secret_Key, 'response': recaptcha_response}
            response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
            result = response.json()
            recaptchaSuccess = False
            if result.get('success'):
              recaptchaSuccess = True
            else:
              recaptchaSuccess = False
            if recaptchaSuccess == False:
              flash("reCaptcha Response failed. Try again")
              return render_template('login.html', form=LoginForm())
            
            email = session['email']
            user_id = session['user_id']
            #email = request.form['email_hidden'].lower()
            optin = 'no'
            if request.form['options']:
              optin = str(request.form['options']).lower()
            user = db.session.query(User).filter(User.email == email, User.user_verified == 1,User.id == user_id).one_or_none()
            if user:
                user_optin = False
                user_optout = True
                firstname = sanitize_input(request.form["firstname"].strip())
                lastname = sanitize_input(request.form["lastname"].strip())
                user.first_name = firstname
                user.last_name = lastname
                #user.passphrase = getHash(request.form['passphrase'])
                db.session.add(user)
                db.session.commit()
                db.session.flush(objects=[user])
                if optin:
                  useroptin = User_Optin()
                  useroptin.user_id = user.id
                  if optin == 'yes':
                     useroptin.user_optin = 1
                     user_optin = True
                     user_optout = False
                  else:
                     useroptin.user_optin = 0
                     user_optin = False
                     user_optout = True
                  useroptin.created_date = datetime.datetime.utcnow()
                  useroptin.updated_date = datetime.datetime.utcnow()
                  db.session.add(useroptin)
                  db.session.commit()
                  db.session.flush(objects=[useroptin])
                flash("Profile updated successfully")
                return render_template('profile.html', email=user.email, firstname=user.first_name, lastname=user.last_name,optinto=user_optin,optout=user_optout)
            flash("Profile updated successfully")
            return render_template('profile.html', email=user.email, firstname=user.first_name, lastname=user.last_name,optinto=user_optin,optout=user_optout)
          
        flash("Something went wrong. Please try again later.")
        return render_template('login.html', email=email)
    except Exception as err:
        logging.error('An error occurred during profile request: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('login.html', form=LoginForm())

def getAdminList():
  try:
    listAdm = list[str]()
    user = db.session.query(User).filter(User.email == 'patrick@gratitech.com', User.user_verified == 1,).one_or_none()
    if user:
      user.subscribed = 1
      db.session.add(user)
      db.session.commit()
      db.session.flush(user) 
    listAdm.append('mk@gratitech.com')
    listAdm.append('patrick@gratitech.com')
    listAdm.append('pmkelly2@aishields.org')
    listAdm.append('patrickkelly2024@u.northwestern.edu')
    listAdm.append('patrickkelly2015@u.northwestern.edu')
    return listAdm  
  except Exception as err:
        logging.error('An error occurred during building the admin role list of users getAdminList(): %s', err)
        flash("An error occurred. Please try again.")
        return render_template('login.html', form=LoginForm())
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        form = LoginForm()
        if request.method == "GET":
             return render_template('login.html', form=LoginForm())
        if form.validate_on_submit():
            try:
                # check recaptcha and for valid email:
                recaptcha_response = request.form.get('g-recaptcha-response')
                payload = {'secret': sc.GOOGLE_Recaptcha_Secret_Key, 'response': recaptcha_response}
                response = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
                result = response.json()
                recaptchaSuccess = False
                if result.get('success'):
                  recaptchaSuccess = True
                else:
                  recaptchaSuccess = False
                if recaptchaSuccess == False:
                  flash("reCaptcha failed. Try again")
                  return render_template('login.html', form=LoginForm())
                
                email = form.email.data.lower()
                passphrase = getHash(form.passphrase.data)
                user = (db.session.query(User).filter(
                    User.email == email, 
                    User.passphrase == passphrase, 
                    User.user_verified == 1,
                    User.subscribed == 1,
                ).first())
                adminlist = [str]
                adminlist = getAdminList()
                if user is not None:
                    session['logged_in'] = True
                    session['user_id'] = user.id
                    session['email'] = user.email
                    session['username'] = f"{user.first_name} {user.last_name}"
                    #session['user_info'] = User_Info()
                    admrole = False
                    for admuser in adminlist:
                       if admuser == user.email:
                          admrole = True
                    if admrole:
                       session['role'] = 'admrole'
                    else:
                       session['role'] = 'userrole'
                    InputPromptHistory = (db.session.query(InputPrompt).filter(InputPrompt.user_id == user.id))
                    chathistory = {}
                    for prmpt in InputPromptHistory:
                        chathistory[prmpt.internalPromptID]=prmpt.inputPrompt
                    return render_template('chat.html',role=session['role'], InputPromptHistory=chathistory,email=user.email,username=user.first_name + " " + user.last_name,apis=apis,output=False,Logged_in=True)   
                else:
                    email = form.email.data.lower()
                    passphrase = getHash(form.passphrase.data)
                    user = (db.session.query(User).filter(
                        User.email == email, 
                        User.passphrase == passphrase, 
                        User.user_verified == 1,
                        User.subscribed == 0,
                    ).first())
                    if user is not None:
                      flash("Please subscribe, we were unable to find an account with the information you entered that is subscribed.")
                      return render_template('subscribe.html',email=email)
                    else:
                      flash("The information you entered did not match our records, if you already have an account we suggest you change your password using the forgot link or create a new account using the join link.")
                      return render_template('login.html',form=LoginForm()) 
 
            except Exception as err:
                logging.error('An error occurred during login: %s', err)
                flash("An error occurred. Please try again.")
                return render_template('login.html', form=LoginForm())

    except Exception as err:
        logging.error('An error occurred during login: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('login.html', form=LoginForm())
 

@app.route('/logout')
def logout():
    try:
        session.clear()
        flash("You have been logged out.")
        form = LoginForm()
        return render_template('login.html',form=form)
    except Exception as err:
        logging.error('An error occurred during logout: %s', err)
        flash("An error occurred. Please try again.")
        return render_template('login.html', form=LoginForm())
    
def generate_response(user_input:User_Info):
    with app.app_context():
        try:
            user_input_internalID = str(user_input.internalID) if isinstance(user_input.internalID, tuple) else user_input.internalID
            user_input_username = str(user_input.username) if isinstance(user_input.username, tuple) else user_input.username
            user_input_email = str(user_input.email) if isinstance(user_input.email, tuple) else user_input.email
            user_input_api = str(user_input.api) if isinstance(user_input.api, tuple) else user_input.api
            user_input_inputprompt = str(user_input.inputprompt) if isinstance(user_input.inputprompt, tuple) else user_input.inputprompt
            user_input_id = int(str(user_input.userid)) if isinstance(user_input.userid, tuple) else user_input.userid
            user_input_model = str(user_input.strModel) if isinstance(user_input.strModel, tuple) else user_input.strModel
            user_input_strApi = str(user_input.strApi) if isinstance(user_input.strApi, tuple) else user_input.strApi

            rawInput = InputPrompt(
                internalPromptID=user_input_internalID,
                user_id=user_input_id,
                username=user_input_username,
                email=user_input_email,
                api=user_input_api,
                inputPrompt=user_input_inputprompt
            )
            element_id = "reportid"
            response = {"message": user_input_internalID, "element_id": element_id}
            yield f"data: {json.dumps(response)}\n\n-jsonEnd;"

            db.session.add(rawInput)
            db.session.commit()
            db.session.flush(objects=[rawInput])
            rawInputObj = db.session.query(InputPrompt).filter(InputPrompt.internalPromptID == user_input_internalID).one_or_none()
            apiObj = db.session.query(GenApi).filter(GenApi.model == user_input_model, GenApi.api_owner == user_input_strApi).one_or_none()
            strRole = 'user'
            element_id = "reportid"
            response = {"message": "AI Shields is Analyzing your Prompt ...", "element_id": element_id}
            yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
            element_id = "AiShields Prompt Injection Report"
            #promptInjectionReport = aishields_promptInjection_check(rawInputObj)
            #response = {"message": promptInjectionReport, "element_id": element_id}
           # yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
            #time.sleep(5)
            if apiObj:
                if user_input.sensitiveData:
                   preprocessedPromptString = aishields_sanitize_input(rawInput)
                   if (sanitize_input(preprocessedPromptString) != preprocessedPromptString):
                     element_id = "AiShields Sensitive Data Report"
                     response = {"message": "~~~ AI Shields found CUI|PII in your input, no worries, it was Redacted and we sent this message:** " + preprocessedPromptString, "element_id": element_id}
                     yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                   else:
                    element_id = "AiShields Sensitive Data Report"
                    response = {"message": "~~~ AI Shields Did not find CUI|PII in your input.", "element_id": element_id}
                    yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                else:
                   preprocessedPromptString = aishields_sanitize_input(rawInput)
                   if preprocessedPromptString == rawInput.inputPrompt:
                    element_id = "AiShields Sensitive Data Report"
                    response = {"message": "~~~ AI Shields Did not find CUI|PII in your input.", "element_id": element_id}
                    yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                   else:
                    element_id = "AiShields Sensitive Data Report"
                    response = {"message": "~~~ AI Shields found Potential CUI|PII in your input: ** " + rawInput.inputPrompt + " **Since your Shield was down this data was included.", "element_id": element_id}
                    yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                    preprocessedPromptString = rawInput.inputPrompt
                #element_id = "preProcStr"
                #response = {"message": preprocessedPromptString, "element_id": element_id}
                #yield f"data: {json.dumps(response)}\n\n-jsonEnd;"

                preprocessedPrompt = PreProcInputPrompt(
                    internalPromptID=user_input_internalID,
                    user_id=user_input_id,
                    api_id=apiObj.id,
                    api=apiObj.uri,
                    email=user_input_email,
                    rawInputPrompt_id=rawInputObj.id,
                    inputPrompt=rawInput.inputPrompt,
                    preProcInputPrompt=preprocessedPromptString,
                    username=user_input_username,
                    SensitiveDataSanitizerReport=str(preprocessedPromptString),
                    PromptInjectionReport = "",
                    OverrelianceReport="",
                    OverrelianceKeyphraseData=""
                )
                db.session.add(preprocessedPrompt)
                db.session.commit()
                db.session.flush(objects=[preprocessedPrompt])
                injectionDetection = True

                strTempApiKey = "" #str(user_input.strEncToken)
                strRawOutput = ""
                three_hours_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
                openaiusermessages = list[dict]
                perplexitymessages = list[dict]
                anthropicmessages = list[dict]
                google2waymessages = list[dict]
                googleusermessages = list[str]
                googleassistantmessages = list[str]                
                #for messageitem in user_input.messages:
                 # newmessage = {"role": strRole.lower(), "content": messageitem} 
                  # openaiusermessages.append(newmessage)
                  # perplexitymessages.append(
                  #               {
                  #                   "role": "system",
                  #                   "content": (
                  #                       "You are an artificial intelligence assistant and you need to "
                  #                       "engage in a helpful, detailed, polite conversation with a user."
                  #                   ),
                  #               })
                  # perplexitymessages.append({
                  #                   "role": "user",
                  #                   "content": (
                  #                       messageitem
                  #                   ),
                  #               },
                  #             )
                if user_input.strApi.lower() == "openai":
                    openaiPrompts = list[InputPrompt]()
                    openaiPrompts = (db.session.query(InputPrompt.internalPromptID).filter(InputPrompt.created_date > three_hours_ago).filter(InputPrompt.api == user_input.strApi).filter(InputPrompt.email == user_input.email).all())
                    #openaiUserPrompts = (db.session.query(PreProcInputPrompt.preProcInputPrompt).filter(PreProcInputPrompt.internalPromptID in openaiPrompts).all())
                    #openaiResponses = (db.session.query(ApiResponse.rawoutput).filter(ApiResponse.internalPromptID in openaiPrompts).all())
                    
                    user_input.openaimessages = list[dict]()
                    for chat in openaiPrompts:
                      userchat = (db.session.query(PreProcInputPrompt.preProcInputPrompt).filter(PreProcInputPrompt.internalPromptID == chat).filter(ApiResponse.email == user_input.email).first())
                      usermessage = {"role": "user", "content": userchat} 
                      user_input.openaimessages.append(usermessage)
                      openaichat = (db.session.query(ApiResponse.rawoutput).filter(ApiResponse.internalPromptID == chat).filter(ApiResponse.email == user_input.email).first())
                      chatresponse = {"role": "assistant", "content": openaichat}
                      user_input.openaimessages.append(chatresponse)                    
                    newmessage = {"role": strRole.lower(), "content": preprocessedPromptString} 
                    user_input.openaimessages.append(newmessage)
                    strTempApiKey = str(decStandard(sc.OPEN_AI_K))
                    preresponse = {"message": "   OpenAI "+ user_input_model + " response: ", "element_id": "responseHeader"}
                    yield f"data: {json.dumps(preresponse)}\n\n-jsonEnd;" 
                    client = openai.Client(api_key=strTempApiKey)
                    stream = client.chat.completions.create(
                        model=user_input_model,
                        messages=user_input.openaimessages,
                        stream=True,
                    )
                    element_id = "rawResponse"
                    for chunk in stream:
                        if chunk.choices[0].delta.content:
                            response = {"message": sanitize_input(chunk.choices[0].delta.content), "element_id": element_id}
                            yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                            strRawOutput += chunk.choices[0].delta.content
                    newresponse = {"role": "assistant", "content": strRawOutput} 
                    user_input.openaimessages = list[dict]()
                    openaiPrompts = list[InputPrompt]()
                elif user_input.strApi.lower() == "anthropic":
                    anthropicPrompts = list[InputPrompt]()
                    user_input.anthropicmessages = list[dict]()
                    anthropicPrompts = (db.session.query(InputPrompt.internalPromptID).filter(InputPrompt.created_date > three_hours_ago).filter(InputPrompt.api == user_input.strApi).filter(InputPrompt.email == user_input.email).all())
                    for chat in anthropicPrompts:
                      userchat = (db.session.query(PreProcInputPrompt.preProcInputPrompt).filter(PreProcInputPrompt.internalPromptID == chat).filter(ApiResponse.email == user_input.email).first())
                      usermessage = {"role": "user", "content": userchat} 
                      user_input.anthropicmessages.append(usermessage)
                      anthropicchat = (db.session.query(ApiResponse.rawoutput).filter(ApiResponse.internalPromptID == chat).filter(ApiResponse.email == user_input.email).first())
                      chatresponse = {"role": "assistant", "content": anthropicchat}
                      user_input.anthropicmessages.append(chatresponse)                    
                    newmessage = {"role": strRole.lower(), "content": preprocessedPromptString} 
                    user_input.anthropicmessages.append(newmessage)
                    strTempApiKey = str(decStandard(sc.ANTHROPIC_K))
                    preresponse = {"message": "   Anthropic "+ user_input_model + " response: ", "element_id": "responseHeader"}
                    yield f"data: {json.dumps(preresponse)}\n\n-jsonEnd;"
                    client = anthropic.Anthropic(api_key=strTempApiKey)
                    element_id = "rawResponse"
                    with client.messages.stream(
                        model=user_input_model,
                        max_tokens=1024,
                        messages=user_input.anthropicmessages
                        ) as stream:
                      for text in stream.text_stream:
                        strRawOutput += text
                        response = {"message": sanitize_input(text), "element_id": element_id}
                        yield f"data: {json.dumps(response)}\n\n-jsonEnd;" 
                    newresponse = {"role": "assistant", "content": strRawOutput} 
                    user_input.anthropicmessages.append(newresponse)
                    user_input.anthropicmessages = list[dict]()   
                elif user_input.strApi.lower() == "google":
                    googlePrompts = list[InputPrompt]()
                    googlePrompts = (db.session.query(InputPrompt.internalPromptID).filter(InputPrompt.created_date > three_hours_ago).filter(InputPrompt.api == user_input.strApi).filter(InputPrompt.email == user_input.email).all())
                    gfullmessage = list[dict]()
                    googleusersmessages = list[str]()
                    googleResponses = list[str]()
                    for chat in googlePrompts:
                      userchat = (db.session.query(PreProcInputPrompt.preProcInputPrompt).filter(PreProcInputPrompt.internalPromptID == chat).filter(ApiResponse.email == user_input.email).first())
                      googleusersmessages.append(userchat) 
                      googlechat = (db.session.query(ApiResponse.rawoutput).filter(ApiResponse.internalPromptID == chat).filter(ApiResponse.email == user_input.email).first())
                      googleResponses.append(googlechat)
                    googleusersmessages.append(preprocessedPromptString)
                    gumessages =  "[" + ",".join(f"'{s}'" for s in googleusersmessages) + "]"
                    gfullmessage.append({'role':'user','parts':gumessages})
                    if len(googleResponses) >= 1:
                      gmessages =  "[" + ",".join(f"'{s}'" for s in googleResponses) + "]"
                      gfullmessage.append({'role':'model','parts':gmessages})
                    element_id = "rawResponse"
                    preresponse = {"message": "   Google "+ user_input_model + " response: ", "element_id": "responseHeader"}
                    yield f"data: {json.dumps(preresponse)}\n\n-jsonEnd;" 
                    strTempApiKey = str(decStandard(sc.GOOGLE_K))
                    googlegenai.configure(api_key=strTempApiKey)
                    model = googlegenai.GenerativeModel(user_input_model)
                    response = model.generate_content(gfullmessage,stream=True)
                    for chunk in response:
                      gRawOutput = sanitize_input(chunk.text)
                      responseg = {"message": gRawOutput, "element_id": element_id}
                      yield f"data: {json.dumps(responseg)}\n\n-jsonEnd;"
                      strRawOutput += gRawOutput
                    googleusersmessages = list[str]()
                    googleResponses = list[str]()
                    #user_input.googlemessages.append({'role':'model','parts':strRawOutput})  
                elif user_input.strApi == "Perplexity":
                    perplexityPrompts = list[InputPrompt]()
                    perplexityPrompts = (db.session.query(InputPrompt.internalPromptID).filter(InputPrompt.created_date > three_hours_ago).filter(InputPrompt.api == user_input.strApi).filter(InputPrompt.email == user_input.email).all())
                    perplexitymessages = list[dict]()
                    for chat in perplexityPrompts:
                      userchat = (db.session.query(PreProcInputPrompt.preProcInputPrompt).filter(PreProcInputPrompt.internalPromptID == chat).first())
                      perplexitymessages.append({
                                      "role": "user",
                                    "content": (
                                        userchat
                                    ),
                                }
                              )
                      perplexityResponse = (db.session.query(ApiResponse.rawoutput).filter(ApiResponse.internalPromptID == chat).first())  
                      perplexitymessages.append({
                                      "role": "assistant",
                                    "content": (
                                        perplexityResponse
                                    ),
                                })
                    element_id = "rawResponse"
                    perplexitymessages.append({
                                      "role": "user",
                                    "content": (
                                        preprocessedPromptString
                                    ),
                                }
                              )
                    messages = list[dict]()
                    messages = perplexitymessages
                    preresponse = {"message": "   Perplexity.ai "+ user_input_model + " response: ", "element_id": "responseHeader"}
                    yield f"data: {json.dumps(preresponse)}\n\n-jsonEnd;" 
                    strTempApiKey = sc.PERPLEXITY_K
                    client = openai.Client(api_key=str(strTempApiKey), base_url="https://api.perplexity.ai")
                    response_stream = client.chat.completions.create(
                        model=user_input_model,
                        messages=messages,
                        stream=True,
                        )
                    for chunk in response_stream:
                        if chunk.choices[0].delta.content:
                            response = {"message": sanitize_input(chunk.choices[0].delta.content), "element_id": element_id}
                            yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                            strRawOutput += chunk.choices[0].delta.content
                    perplexitymessages.append({
                              "role": "assistant",
                            "content": (
                                strRawOutput
                            ),
                        })
                    user_input.perplexitymessages = perplexitymessages
                    messages = list[dict]()
                else:
                    flash(user_input.strApi + " support will be available soon!")
                # now add html to mark the end of the raw output:
                # element_id = "rawResponse"
                # strRawOutputEnd = "<hr/>"
                # response = {"message": strRawOutputEnd, "element_id": element_id}
                # yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                #user_input.messages.append()
                rawOutput = ApiResponse(
                    internalPromptID=user_input_internalID,
                    user_id=user_input_id,
                    api_id=apiObj.id,
                    api=apiObj.uri,
                    email=user_input_email,
                    preProcPrompt_id=preprocessedPrompt.id,
                    rawInputPrompt_id=rawInput.id,
                    rawoutput=strRawOutput,
                    externalPromptID="",
                    username=user_input_username,
                )
                db.session.add(rawOutput)
                db.session.commit()
                db.session.flush(objects=[rawOutput])
                rawOutputObj = db.session.query(ApiResponse).filter(ApiResponse.internalPromptID == user_input_internalID).one_or_none()
                preProcObj = db.session.query(PreProcInputPrompt).filter(PreProcInputPrompt.internalPromptID == user_input_internalID).one_or_none()
                postProcPromptObj = PostProcResponse(
                    rawInputPrompt_id=rawInputObj.id,
                    inputPromptID=user_input_internalID,
                    preProcPrompt_id=preProcObj.id,
                    externalPromptID=rawOutput.externalPromptID,
                    user_id=user_input_id,
                    username=user_input_username,
                    email=user_input_email,
                    api_id=apiObj.id,
                    api=apiObj.uri,
                    rawResponseID=rawOutputObj.id,
                    rawOutputResponse=rawOutputObj.rawoutput,
                    postProcOutputResponse="",
                    InsecureOutputHandlingReport="",
                    created_date=datetime.datetime.now(datetime.timezone.utc)
                )
                element_id = "response"
                postProcPromptObj = aishields_postprocess_output(postProcPromptObj)
                response = {"message": postProcPromptObj.postProcOutputResponse, "element_id": element_id}
                yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                #promptInjectionReport = aishields_promptInjection_check(rawInputObj)
                #preProcObj.PromptInjectionReport = promptInjectionReport
                db.session.add(preProcObj)
                db.session.add(postProcPromptObj)
                db.session.commit()
                db.session.flush(objects=[postProcPromptObj,preProcObj])
                aiShieldsReportObj = AiShieldsReport(
                    rawInputPrompt_id=rawInputObj.id,
                    internalPromptID=user_input_internalID,
                    preProcPrompt_id=preProcObj.id,
                    externalPromptID=rawOutput.externalPromptID,
                    user_id=user_input_id,
                    username=user_input_username,
                    email=user_input.email,
                    api_id=apiObj.id,
                    api=apiObj.uri,
                    rawResponse_id=rawOutputObj.id,
                    postProcResponse_id=postProcPromptObj.id,
                    SensitiveDataSanitizerReport=preProcObj.SensitiveDataSanitizerReport,
                    #PromptInjectionReport=promptInjectionReport,
                    OverrelianceReport=preProcObj.OverrelianceReport,
                    InsecureOutputReportHandling=postProcPromptObj.InsecureOutputHandlingReport,
                    MDOSreport=getMDOSreport(rawInputObj),
                    created_date=datetime.datetime.now(datetime.timezone.utc),
                    updated_date=datetime.datetime.now(datetime.timezone.utc)
                )
                db.session.add(aiShieldsReportObj)
                db.session.commit()
                db.session.flush(objects=[aiShieldsReportObj])
                element_id = "reportid"
                response = {"message": user_input_internalID, "element_id": element_id}
                yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                #time.sleep(5)
                # element_id = "AiShields Sensitive Data Report"
                # response = {"message": aiShieldsReportObj.SensitiveDataSanitizerReport, "element_id": element_id}
                # yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                # ##time.sleep(5)
                # #element_id = "AiShields Prompt Injection Report"
                #response = {"message": aiShieldsReportObj.PromptInjectionReport, "element_id": element_id}
               # yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                #time.sleep(5)
                element_id = "AiShields MDOS Report"
                response2 = {"message": aiShieldsReportObj.MDOSreport, "element_id": element_id}
                yield f"data: {json.dumps(response2)}\n\n-jsonEnd;"
                #time.sleep(5)
                element_id = "AiShields Insecure Output Handling Report"
                response3 = {"message": aiShieldsReportObj.InsecureOutputReportHandling, "element_id": element_id}
                yield f"data: {json.dumps(response3)}\n\n-jsonEnd;"
                # findings = [
                #     {"category": "AiShields Sensitive Data", "details": aiShieldsReportObj.SensitiveDataSanitizerReport, "id": aiShieldsReportObj.internalPromptID},
                #     {"category": "AiShields Prompt Injection", "details": aiShieldsReportObj.PromptInjectionReport, "id": aiShieldsReportObj.internalPromptID},
                #     {"category": "AiShields MDOS", "details": aiShieldsReportObj.MDOSreport, "id": aiShieldsReportObj.internalPromptID},
                #     {"category": "AiShields Insecure Output Handling", "details": aiShieldsReportObj.InsecureOutputReportHandling, "id": aiShieldsReportObj.internalPromptID},
                # ]
                # for finding in findings:
                #     response = {"message": finding["details"], "element_id": finding["category"] + " Report"}
                #     yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                if user_input.overrelianceData:
                  plot,preProcObj = aishields_overreliance_postProc(input=rawOutput,preproc=preProcObj,postproc=postProcPromptObj,rawinput=rawInputObj)
                  response = {"message": preProcObj.OverrelianceReport, "element_id": "AiShields Overreliance Report"}
                  yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                  # preProcObj.OverrelianceReport = plot + ' ' + preProcObj.OverrelianceReport
                  # response = {"message": plot, "element_id": "overreliance"}
                  # yield f"data: {json.dumps(response)}\n\n-jsonEnd;" 
                  aiShieldsReportObj.OverrelianceReport = preProcObj.OverrelianceReport
                  db.session.add(aiShieldsReportObj)
                  db.session.add(preProcObj)
                  db.session.commit()
                  db.session.flush(objects=[aiShieldsReportObj,preProcObj])   
                    # plot,preProcObj = aishields_overreliance_postProc(input=rawOutput,preproc=preProcObj,postproc=postProcPromptObj,rawinput=rawInputObj)
                    # response = {"message": preProcObj.OverrelianceReport, "element_id": "AiShields Overreliance Report"}
                    # yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                    # response = {"message": plot, "element_id": "overreliance"}
                    # yield f"data: {json.dumps(response)}\n\n-jsonEnd;" 
                    # response = {"message": preProcObj.OverrelianceReport, "element_id": "overreliance"}
                    # yield f"data: {json.dumps(response)}\n\n-jsonEnd;" 
                    # preProcObj.OverrelianceReport += '<br/>' + plot
                    # db.session.add(preProcObj)
                    # db.session.commit()
                    # db.session.flush(objects=[preProcObj])
                #yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
                #preprocessedPrompt = aishields_overreliance_postProc(rawInput, preprocessedPrompt, postProcPromptObj, rawInput)
                #preprocessedPrompt.PromptInjectionReport = promptInjectionReport
               # response = {"message": preprocessedPrompt.OverrelianceReport, "element_id": "AiShields Overreliance Report"}
               # yield f"data: {json.dumps(response)}\n\n-jsonEnd;"
               # db.session.add(preprocessedPrompt)
               # db.session.commit()
               # db.session.flush(objects=[preprocessedPrompt])
           # return Response(stream_with_context(generate_response(user_)), content_type='text/event-stream')
        except Exception as err:
            logging.error('An error occurred during chat processing: %s', err)
            error_response = {"message": "An error occurred. Please try again later.", "element_id": "error"}
            yield f"data: {json.dumps(error_response)}\n\n-jsonEnd;"


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    try:
        headers = {
        'Cache-Control': 'no-cache',
        'Content-Type': 'text/event-stream'
        }
        if not session.get('logged_in'):
            error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
            return Response(f"data: {json.dumps(error_response)}\n\n-jsonEnd;",headers=headers), 401
        role = session.get('role')
        user = db.session.query(User).filter(User.email == session['email'], User.user_verified == 1, User.subscribed == 1).first()
        if not user:
            error_response = {"message": "User not found or not subscribed. Please <a href='/join'>Join</a>", "element_id": "error"}
            return Response(f"data: {json.dumps(error_response)}\n\n-jsonEnd;",headers=headers), 401
        InputPromptHistory = (db.session.query(InputPrompt).filter(InputPrompt.user_id == user.id))
        chathistory={}
        for prmpt in InputPromptHistory:
            chathistory[prmpt.internalPromptID]=prmpt.inputPrompt
        if request.method == 'GET':
            # Handle GET requests for fetching chat history
            chatId = request.args.get('chat')
            if chatId:
                rawInput = (db.session.query(InputPrompt).filter(InputPrompt.internalPromptID == chatId, InputPrompt.user_id == user.id).first())
                if rawInput is not None:
                    preprocPrompt = (db.session.query(PreProcInputPrompt).filter(PreProcInputPrompt.internalPromptID == str(chatId)).first())
                    if preprocPrompt:
                        postProcResp = (db.session.query(PostProcResponse).filter(PostProcResponse.inputPromptID == str(chatId)).first())
                        if postProcResp:
                            aiShieldsReport = (db.session.query(AiShieldsReport).filter(AiShieldsReport.internalPromptID == str(chatId)).first())
                            if aiShieldsReport:
                                rawInputStr = rawInput.inputPrompt
                                #preprocPromptStr = preprocPrompt.preProcInputPrompt
                                apiResponse = (db.session.query(ApiResponse).filter(ApiResponse.internalPromptID == str(chatId)).first())
                                if apiResponse:
                                    rawOutputStr = apiResponse.rawoutput
                                    apiStr = rawInput.api
                                    postProcRespStr = postProcResp.postProcOutputResponse
                                    findings = [
                                        {"category": "Sensitive Data", "details": aiShieldsReport.SensitiveDataSanitizerReport, "id": aiShieldsReport.internalPromptID},
                                        {"category": "Prompt Injection", "details": aiShieldsReport.PromptInjectionReport, "id": aiShieldsReport.internalPromptID},
                                        {"category": "Overreliance", "details": aiShieldsReport.OverrelianceReport, "id": aiShieldsReport.internalPromptID},
                                        {"category": "MDOS", "details": aiShieldsReport.MDOSreport, "id": aiShieldsReport.internalPromptID},
                                       {"category": "Insecure Output Handling", "details": aiShieldsReport.InsecureOutputReportHandling, "id": aiShieldsReport.internalPromptID}
                                    ]
                                    return render_template('chat.html', inputprompt=rawInputStr,recalloutput='  Output from '+ apiStr + ' : <br/>'+ sanitize_input(rawOutputStr),rawInput=sanitize_input(rawInput.inputPrompt), preProcStr=preprocPrompt.preProcInputPrompt, rawResponse=sanitize_input(rawOutputStr), InputPromptHistory=chathistory, PostProcResponseHistory=postProcRespStr, apis=apis, email=session['email'], username=session['username'], response=postProcRespStr, findings=findings, output=True, logged_in=True,role=session['role'])
            user_input = str(request.args.get('user_input'))
            user_api = str(request.args.get('api'))
            current_user = User_Info()
            #user_tkn = str(request.args.get('apit'))
            if user_input != 'None' and user_api != 'None': # and user_tkn:
                current_user.api=user_api
                current_user.username=session.get('username')
                current_user.email=session.get('email')
                current_user.inputprompt=user_input
                current_user.internalID=str(uuid.uuid4())
                current_user.strApi=user_api.split(' ')[0]
                current_user.strModel=user_api.split(' ')[1]
                current_user.userid=user.id
                current_user.messages = session.get('messages')
                current_user.messages.append(user_input)
                
                #user_info.messages.append(user_input)
                

                if not current_user.api or not current_user.inputprompt or not current_user.username or not current_user.email:
                    flash("Please fill out all required fields.")
                    error_response = {"message": "Please fill out all required fields.", "element_id": "validationerror"}
                    return Response(f"data: {json.dumps(error_response)}\n\n-jsonEnd;",headers=headers), 400

                return Response(stream_with_context(generate_response(current_user)),headers=headers)
            return render_template('chat.html',role=session['role'], findings=[],InputPromptHistory=chathistory, apis=apis, email=session['email'], username=session['username'], logged_in=True) 
        elif request.method == 'POST':
            if not session.get('logged_in'):
                error_response = {"message": "Not logged in, please <a href='/login'>login</a>", "element_id": "error"}
                return Response(f"data: {json.dumps(error_response)}\n\n-jsonEnd;",headers=headers), 401
            if request.form.get('api') and session.get('username') and request.form.get("chat"):
              user_info = User_Info()
              user_info.api=request.form.get('api')
              user_info.username=session.get('username')
              user_info.email=session.get('email')
              user_info.inputprompt=request.form.get('chat')
              user_info.internalID=str(uuid.uuid4())
              user_info.strApi=request.form.get('api').split(' ')[0]
              user_info.strModel=request.form.get('api').split(' ')[1]
              user_info.userid=user.id
            else:
              return Response(f"data: {json.dumps("Error: Missing api parameter")}\n\n-jsonEnd;", headers=headers), 400
 
              #user_info.messages = session.get('messages')
            #user_info.messages.append(user_info.inputprompt)
            #session['messages'] = user_info.messages
                
            #user_info.messages.append(user_info.inputprompt)
                
            if request.form.get('sensitiveData') == 't':
               user_info.sensitiveData = True
            else:
               user_info.sensitiveData = False
            if request.form.get('overrelianceData')=='t':
               user_info.overrelianceData = True
            else:
               user_info.overrelianceData = False

            if not user_info.api or not user_info.inputprompt or not user_info.username or not user_info.email:
                flash("Please fill out all required fields.")
                error_response = {"message": "Please fill out all required fields.", "element_id": "validationerror"}
                return Response(f"data: {json.dumps(error_response)}\n\n-jsonEnd;", headers=headers), 400

            return Response(generate_response(user_info),headers=headers)
    except Exception as err:
        logging.error('An error occurred during chat processing: %s', err)
        flash(err)
        return render_template('chat.html', role=session['role'],InputPromptHistory={}, apis=apis, email=session['email'], username=session['username'], logged_in=True)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('CSRF Token Expired, Please login again')
    return render_template('login.html', form=LoginForm())
@app.route('/messages/<int:idx>')
def message(idx):
    messages = ['System Unavailable due to Maintenance', 'Session Expired, please Login again.']
    return render_template('messages.html', message=messages[idx])
# @app.route('/dump')
# def dump_database():
#     dump_file = 'AiShields-database_dump.sql'
#     with open(dump_file, 'w', encoding='utf-8') as f:
#         for line in db.engine.raw_connection().iterdump():
#             f.write(f'{line}\n')
#     return f"Database dump created at {os.path.abspath(dump_file)}"


def getMDOSreport(input:InputPrompt):
        #sensitive data sanitization:
        # now sanitize for privacy protected data
    try:
        prompt = input.inputPrompt

        # Instantiate the analyzer
        analyzer = PromptAnalyzer()
        
        # Analyze the prompt
        is_expensive = analyzer.is_expensive_prompt(prompt)
        complexity = analyzer.complexity_metric(prompt)

        # Return the results as a dictionary
        result = {
            "prompt": prompt,
            "is_expensive": is_expensive,
            "complexity_metric": complexity
        }
        MDosOutputString = ""
        for key in result.keys():
            MDosOutputString += str(key) + " : " + str(result[key]) + " "
        return MDosOutputString
        #return f"is_expensive: {result["is_expensive"]}  complexity_metric: {result["complexity_metric"]}"  
    except Exception as err:
        logging.error('An error occurred while generating the MDOS report: %s', err)
        flash(err)
        #return render_template('login.html', form=LoginForm())
 

def aishields_sanitize_input(input:InputPrompt):
        #sensitive data sanitization:
        # now sanitize for privacy protected data
    try:
        strPreProcInput = ""
        strRawInputPrompt = input.inputPrompt
        sanitizedInput = sanitize_input(strRawInputPrompt)

        sds = SensitiveDataSanitizer()
        strSensitiveDataSanitized = sds.sanitize_text(input_content=sanitizedInput)           
        strPreProcInput += str(strSensitiveDataSanitized)
        #now sanitize for Prompt Injection
        #now assess for Overreliance
        return strPreProcInput
    except Exception as err:
        logging.error('An error occurred during input sanitization: %s', err)
        flash(err)
        
def aishields_sanitize_output(postProcResponseObj: PostProcResponse):
        try:
            strPreProcOutput = ""
            strRawOutputPrompt = postProcResponseObj.rawOutputResponse
            sds = SensitiveDataSanitizer()
            strSensitiveDataSanitized = sds.sanitize_text(input_content=strRawOutputPrompt)
            strPreProcOutput += str(strSensitiveDataSanitized)
            return strPreProcOutput
        except Exception as err:
            logging.error('An error occurred during output sanitization: %s', err)
            flash(err)

# def aishields_promptInjection_check(input:InputPrompt):
#         #sensitive data sanitization:
#         # now sanitize for privacy protected data
#     try:
#         """ pio = Prompt_Injection_Sanitizer(sc.,"C:\\Users\\crossfire234\\Desktop\\WorkStuff\\BCAMP\\AiShields\\AiShieldsWeb-5-23-24\\prompt_injection_sanitizer\\models\\jailbreak_vectorizer.bin") """
#         promptInjectionOutput = dict[str,int](prompt_injection_score(str(input.inputPrompt)))
#         promptInjOutputString = ""
#         for key in promptInjectionOutput.keys():
#             promptInjOutputString += str(key) + " : " + str(promptInjectionOutput[key]) + " "
#         return promptInjOutputString
#     except Exception as err:
#         logging.error('An error occurred during prompt injection check: %s', err)
#         flash(err)

# def aishields_overreliance_inputfunc(input:InputPrompt, preproc:PreProcInputPrompt):
#         #sensitive data sanitization:
#         # now sanitize for privacy protected data
#     try:
#         SITE_IGNORE_LIST = ["youtube.com"]
#         NUMBER_OF_SEARCHES = 1
#         NUMBER_OF_LINKS = 1
#         STOPWORD_LIST = ["*", "$"]
        
#         ods = ODS()

#         overreliance_keyphrase_data_list = ods.get_keyphrases_and_links(preproc.preProcInputPrompt,NUMBER_OF_SEARCHES,link_number_limit=NUMBER_OF_LINKS, stopword_list=STOPWORD_LIST)
        
#         overreliance_keyphrase_data_list = ods.get_articles(overreliance_keyphrase_data_list,site_ignore_list=SITE_IGNORE_LIST)
#         #preproc.OverrelianceKeyphraseData = repr(overreliance_keyphrase_data_list)
#         return overreliance_keyphrase_data_list
#     except Exception as err:
#         logging.error('An error occurred durring overreliance input processing: %s', err)
#         flash(err)

def aishields_overreliance_postProc(input:ApiResponse,preproc:PreProcInputPrompt, postproc:PostProcResponse,rawinput:InputPrompt):
        #sensitive data sanitization:
        # now sanitize for privacy protected data
    from overreliance.overreliance_script import overreliance_pipeline as op
    try:
        plot, summary = op(preproc.preProcInputPrompt,postproc.rawOutputResponse)
        preproc.OverrelianceReport = summary
        return plot,preproc
    except Exception as err:
        logging.error('An error occurred during overreliance output processing: %s', err)
        flash(err)

def aishields_postprocess_output(postProcResponseObj:PostProcResponse):
    #insecure output handing
    try:
        #strPostProcessedOutput = sanitize_input(postProcResponseObj.rawOutputResponse)
        output_sanitizer=InsecureOutputSanitizer()
        strPostProcessedOutput, outputSanitizationReport = output_sanitizer.generate_json_report(postProcResponseObj.rawOutputResponse)
        
        postProcResponseObj.postProcOutputResponse = escape(str(strPostProcessedOutput))
        
        
        postProcResponseObj.InsecureOutputHandlingReport = outputSanitizationReport
        #handle and sanitize raw output
        #return post processed Output
        return postProcResponseObj
    except Exception as err:
        logging.error('An error occurred during post processing: %s', err)
        flash(err)
         

def aishields_store_cred(input:Credential):
    try:
        #insecure output handing
        db.session.add(input)
        db.session.commit()
        #handle and sanitize raw output
        #return post processed Output
        return True
    except Exception as err:
        logging.error('An error occurred while attempting to store creds: %s', err)
        flash(err)
          
        
def aishields_add_user():
    try:
        user2add = User(session_id='0x00',provider='AiShields',username=str('Jim Ye'),first_name='Jim',last_name='Ye',email='jye@imberiumglobal.com',passphrase=getHash('Welcom3Jim!'),user_verified=1,subscribed=1,created_date=datetime.datetime.now(datetime.timezone.utc))
        #user2mod = (db.session.query(User).filter(User.id==13668).first())
        #user2mod.user_verified = 1
        #user2mod.subscribed = 1
        #user3add = User(username=str('Mike Mausteller'),first_name='Mike',last_name='Mausteller',email='mike@bbpgrowth.com',passphrase=getHash('Welcom3OM!'),user_verified=1,subscribed=1,created_date=datetime.datetime.now(datetime.timezone.utc))
        # # user2add.first_name = 'Obakeng'
        ## user2add.last_name = 'Mothibedi'
       # # user2add.email = 'obakengmothibedi@gmail.com'
       # # user2add.username = 'Obakeng Mothibedi'
       # # user2add.passphrase = '1'
      #  # user2add.user_verified = 1
       # # user2add.subscribed = 1
        #db.session.add(user2add)
        #db.session.commit()
        #db.session.flush(objects=[user2add])
    except Exception as err:
        logging.error('An error occurred during aishields add user: %s', err)
        #flash(err) 

def aishields_add_model():
    try:
        model2add = GenApi(api_owner=str('Google'),api_name='Gemini',uri='https://generativelanguage.googleapis.com/v2/{model=models/gemini-2.0-flash}:generateContent',headers='',formfields='',model='gemini-2.0-flash-exp',created_date=datetime.datetime.now(datetime.timezone.utc),updated_date=datetime.datetime.now(datetime.timezone.utc))
        # model2add2 = GenApi(api_owner=str('Perplexity'),api_name='Meta',uri='https://api.perplexity.ai/chat/completions',headers='',formfields='',model='llama-3.1-sonar-large-128k-chat',created_date=datetime.datetime.now(datetime.timezone.utc),updated_date=datetime.datetime.now(datetime.timezone.utc))
        # model2add3 = GenApi(api_owner=str('Perplexity'),api_name='Meta',uri='https://api.perplexity.ai/chat/completions',headers='',formfields='',model='llama-3.1-sonar-small-128k-online',created_date=datetime.datetime.now(datetime.timezone.utc),updated_date=datetime.datetime.now(datetime.timezone.utc))
        # model2add4 = GenApi(api_owner=str('Perplexity'),api_name='Meta',uri='https://api.perplexity.ai/chat/completions',headers='',formfields='',model='llama-3.1-sonar-small-128k-chat',created_date=datetime.datetime.now(datetime.timezone.utc),updated_date=datetime.datetime.now(datetime.timezone.utc))
        # model2add5 = GenApi(api_owner=str('Perplexity'),api_name='Meta',uri='https://api.perplexity.ai/chat/completions',headers='',formfields='',model='llama-3.1-8b-instruct',created_date=datetime.datetime.now(datetime.timezone.utc),updated_date=datetime.datetime.now(datetime.timezone.utc))
        # model2add6 = GenApi(api_owner=str('Perplexity'),api_name='Meta',uri='https://api.perplexity.ai/chat/completions',headers='',formfields='',model='llama-3.1-70b-instruct',created_date=datetime.datetime.now(datetime.timezone.utc),updated_date=datetime.datetime.now(datetime.timezone.utc))
       # user2add.first_name = 'Obakeng'
        # user2add.last_name = 'Mothibedi'
        # user2add.email = 'obakengmothibedi@gmail.com'
        # user2add.username = 'Obakeng Mothibedi'
        # user2add.passphrase = '1'
        # user2add.user_verified = 1
        # user2add.subscribed = 1
        db.session.add(model2add)
        # db.session.add(model2add2)
        # db.session.add(model2add3)
        # db.session.add(model2add4)
        # db.session.add(model2add5)
        # db.session.add(model2add6)
        db.session.commit()
        db.session.flush(objects=[model2add]) #,model2add2,model2add3,model2add4,model2add5,model2add6])
        # model2Remove = db.session.query(GenApi).filter(GenApi.model == 'Perplexity.ai: llama-3-sonar-small-32k-chat').first()
        # model2Remove2 = db.session.query(GenApi).filter(GenApi.model == 'Perplexity.ai: llama-3-sonar-small-32k-online').first()
        # model2Remove3 = db.session.query(GenApi).filter(GenApi.model == 'Perplexity.ai: llama-3-sonar-large-32k-chat').first()
        # model2Remove4 = db.session.query(GenApi).filter(GenApi.model == 'Perplexity.ai: llama-3-sonar-large-32k-online').first()
        # model2Remove5 = db.session.query(GenApi).filter(GenApi.model == 'Perplexity.ai: llama-3-70b-instruct').first()
        # model2Remove6 = db.session.query(GenApi).filter(GenApi.model == 'Perplexity.ai: mixtral-8x7b-instruct').first()
        # if not model2Remove:
        #   db.session.delete(model2Remove)
        #   db.session.commit()
        #   db.session.flush(objects=[model2Remove])
        # if not model2Remove2:
        #   db.session.delete(model2Remove2)
        #   db.session.commit()
        #   db.session.flush(objects=[model2Remove2])
        # if not model2Remove3:
        #   db.session.delete(model2Remove3)
        #   db.session.commit()
        #   db.session.flush(objects=[model2Remove3])
        # if not model2Remove4:
        #   db.session.delete(model2Remove4)
        #   db.session.commit()
        #   db.session.flush(objects=[model2Remove4])
        # if not model2Remove5:
        #   db.session.delete(model2Remove5)
        #   db.session.commit()
        #   db.session.flush(objects=[model2Remove5])
        # if not model2Remove6:
        #   db.session.delete(model2Remove6)
        #   db.session.commit()
        #   db.session.flush(objects=[model2Remove6])
        
    except Exception as err:
        logging.error('An error occurred during aishields add model: %s', err)
        #flash(err) 

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # User.__table__.append_column(Column('session', String(), nullable=True))
        # User.__table__.append_column(Column('provider', String(), nullable=True))
        # User.__table__.append_column(Column('subscription_active', bool(), nullable=True, default=False))
        # User.__table__.append_column(Column('trainingdata_optin', bool(), nullable=True, default=False)) 
        # InputPrompt.__table__.append_column(Column('trainingdata_optin',bool(),nullable=True,default=False))
        # # create the new column
        # # Define metadata
        # engine = db.engine
        # Session = sessionmaker(bind=engine)
        # session = Session()
        # metadata = MetaData()
        # metadata.create_all(engine)
        # # commit and flush
        # session.commit()
        # session.flush()
        # print("Column 'provider', session, and subscription_active added successfully to 'users' table.")
        # logging.error("Column 'provider', session, and subscription_active added successfully to 'users' table.")
        #users = []
        # userslist = (db.session.query(User).all())
        #for user in userslist:
            #user.subscription_active = True
        # app.run(debug=True) # only for debugging
       # app.run(debug=True)
        app.run(debug=True, threaded=True)
        
        
