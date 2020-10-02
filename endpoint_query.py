# -*- coding: utf-8 -*-
import hashlib
import hmac
import email
import time
import json
import requests
import logging
from datetime import datetime, timedelta, timezone
from pprint import pprint
from stix.core import STIXPackage
from io import BytesIO, StringIO
from cabby import create_client

class APIRequestHandler(object):
    """Standard class to call FireEye REST API
    
    :var str URL: initial value: 'https://api.isightpartners.com'
    :var str public_key: initial value: ''
    :var str private_key: initial value: ''
    :var str accept_version: initial value: '2.5'
    :var logging.Logger logger: initial value: ``logging.Logger``
    :var requests.Session session: initial value: ``requests.Session()``
    """

    def __init__(self):
        self.URL: str = 'https://api.isightpartners.com'
        self.public_key: str = ''
        self.private_key: str = ''
        self.accept_version: str = '2.5'
        self.session: requests.Session = requests.Session()
        logger: logging.Logger = logging.getLogger(__name__)
        log_level: int = logging.INFO
        logger.setLevel(log_level)
        handler = logging.StreamHandler()
        handler.setLevel(log_level)
        if logger.handlers:
            logger.handlers = []
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        self.logger = logger
    
    def init(self, URL: str = None, public_key: str = None, private_key: str = None, accept_version: str = None, logger: logging.Logger = None, session: requests.Session = None):
        """Initializes class with optional attributes

        :param str URL: URL for FireEye iSight. Defaults to 'https://api.isightpartners.com'
        :param str public_key: Public API Key. Defaults to ''
        :param str private_key: Private API Key. Defaults to ''
        :param str accept_version: FireEye iSight version. Defaults to '2.5'
        :param ``logging.Logger`` logger: Logger object. Defaults to logging.getLogger(__name__)
        :param ``requests.Session`` session: Requests session. Defaults to requests.Session()
        """
        self.URL = URL if URL != None else 'https://api.isightpartners.com'
        self.public_key = public_key if public_key != None else ''
        self.private_key = private_key if private_key != None else ''
        self.accept_version = accept_version if accept_version != None else '2.5'
        self.logger = logger if logger != None else self.logger
        self.session = session if session != None else requests.Session()

    def prepare_headers(self, endpoint: str, accept: str):
        """Attaches headers to handler session

        :param str endpoint: endpoint to hit for hashing
        :param str accept: content type to get for acceptance
        """
        # create timestamp for headers
        time_stamp = email.utils.formatdate(localtime=True)
        new_data = endpoint + self.accept_version + accept + time_stamp
        self.logger.debug(new_data)

        # create hash for headers
        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)
        self.logger.debug(hashed)

        # set header info
        headers = {
            'Accept': accept,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }

        self.session.headers.update(headers)

    def returnHelper(self, response: requests.Response):
        if response.status_code == 200:
            try:
                return_json = response.json()
            except:
                self.logger.error(response.content)
                return response
            return return_json
        else:
            self.logger.error(response.content)
            return response

    def getIocs(self, startDate: datetime = datetime.now() - timedelta(days=7), endDate: datetime = datetime.now(), accept_header: str = 'application/json'):
        """Gets IoCs in a timerange from FireEye iSight API

        :param startDate datetime: Start time. Defaults to ``datetime.now()-timedelta(days=7)``.
        :param endDate datetime: End time. Defaults to ``datetime.now()``.
        :param accept_header str: Mimetype return format. Defaults to 'application/json'.

        :return: Depending on ``accept_header``, returns either dictionary json data or request response
        :rtype: dict OR :class:`request.Response`
        """
        # format endpoint
        startDate = int((startDate - datetime(1970,1,1)).total_seconds())
        endDate  = int((endDate - datetime(1970,1,1)).total_seconds())
        ENDPOINT = '/view/iocs?startDate='+str(startDate)+'&endDate='+str(endDate)

        # get header info for future requests
        self.prepare_headers(ENDPOINT, accept_header)
        self.logger.info( datetime.now().strftime("%d-%m-%Y, %H:%M:%S") + " - Executing request startDate= "+str(startDate) + "&endDate= "+str(endDate) + "\n")

        # execute request
        r = self.session.get(self.URL + ENDPOINT)

        return self.returnHelper(r)

    def getReport(self, reportId: str, accept_header: str = "application/stix"):
        """Gets report endpoint for IoCs

        :param str reportId: ID of report
        :param str accept_header: header to accept different datatypes returned. Defaults to "application/stix".

        :return: Report request response
        :rtype: ``requests.Response``
        """
        ENDPOINT = "/report/" + reportId
        self.logger.info("Getting endpoint " + ENDPOINT)
        self.prepare_headers(ENDPOINT, accept_header)
        r = self.session.get(self.URL + ENDPOINT)

        if accept_header == "application/stix":
            return r.text
        return self.returnHelper(r)

    def uploadFile(self, filename: str, FILE: StringIO):
        """Upload file to search list

        :param str filename: Name of the file you're uploading
        :param StringIO FILE: File-like object

        :return: Return the response
        :rtype: :class:`request.Response`:
        """
        ENDPOINT = '/search/list'
        files = {'file' : (filename, FILE)}
        self.prepare_headers(ENDPOINT, 'application/json')
        r = requests.post(self.URL + ENDPOINT, files=files)
        return self.returnHelper(r)

    def taxiiPush(self, **kwargs):
        """Pushes taxii data to a taxii server
        
        ``jwt_auth_url`` is required for JWT based authentication. If
        it is not specified but ``username`` and ``password`` are provided,
        client will configure Basic authentication.

        SSL authentication can be combined with JWT and Basic
        authentication.

        :param str ca_cert: a path to CA SSL certificate file
        :param str cert_file: a path to SSL certificate file
        :param str key_file: a path to SSL key file
        :param str username: username, used in basic auth or JWT auth
        :param str password: password, used in basic auth or JWT auth
        :param str key_password: same argument as in
            ``ssl.SSLContext.load_cert_chain`` - may be a function to call
            to get the password for decrypting the private key or
            string/bytes/bytearray. It will only be called if the private
            key is encrypted and a password is necessary.
        :param str jwt_auth_url: URL used to obtain JWT token
        :param bool/str verify_ssl: set to False to skip checking host's SSL
            certificate. Set to True to check certificate against public CAs or
            set to filepath to check against custom CA bundle.
        :param str content: content to push
        :param content_binding: content binding for a content
        :type content_binding: string or
                               :py:class:`cabby.entities.ContentBinding`
        :param list collection_names:
                destination collection names
        :param datetime timestamp: timestamp label of the content block
                (current UTC time by default)
        :param str uri: URI path to a specific Inbox Service

        :raises ValueError:
                if URI provided is invalid or schema is not supported
        :raises `cabby.exceptions.HTTPError`:
                if HTTP error happened
        :raises `cabby.exceptions.UnsuccessfulStatusError`:
                if Status Message received and status_type is not `SUCCESS`
        :raises `cabby.exceptions.ServiceNotFoundError`:
                if no service found
        :raises `cabby.exceptions.AmbiguousServicesError`:
                more than one service with type specified
        :raises `cabby.exceptions.NoURIProvidedError`:
                no URI provided and client can't discover services

        :return: STIX object from python-stix
        :rtype: ``stix.core.stix_package.STIXPackage``
        """
        client = create_client()
        content = kwargs.get("content")
        if 'username' in kwargs:
            self.logger.debug("Using basic auth")
            client.set_auth(username=kwargs.get("username"), password=kwargs.get("password"), jwt_auth_url=kwargs.get("jwt_auth_url"), verify_ssl=kwargs.get("verify_ssl"))
        elif 'cert_file' in kwargs:
            self.logger.debug("Using cert auth")
            client.set_auth(ca_cert=kwargs.get("ca_cert"), cert_file=kwargs.get("cert_file"), key_file=kwargs.get("key_file"), key_password=kwargs.get("key_password"), verify_ssl=kwargs.get("verify_ssl"))
        content_io = StringIO(content)
        stix = STIXPackage().from_xml(content_io)
        file_name = stix.id_
        self.logger.info("Pushing STIX " + file_name)
        client.push(
            content=content, 
            content_binding=kwargs.get("content_binding"),
            collection_names=kwargs.get("collection_names"),
            timestamp=kwargs.get("timestamp"),
            uri=kwargs.get("uri")
        )

        return stix
        