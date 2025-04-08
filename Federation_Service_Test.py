# Databricks notebook source
import contextlib
import OpenSSL.crypto
import requests
import tempfile
import re
import json
import urllib
from datetime import date
import pandas as pd

from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

@contextlib.contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    ''' Decrypts the .pfx file to be used with requests. '''
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as t_pem:
        f_pem = open(t_pem.name, 'wb')
        pfx = open(pfx_path, 'rb').read()
        p12 = OpenSSL.crypto.load_pkcs12(pfx, pfx_password)
        f_pem.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))
        f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))
        ca = p12.get_ca_certificates()
        if ca is not None:
            for cert in ca:
                f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        f_pem.close()
        yield t_pem.name

cert_pfx = '.\Certificate.p12'
cert_passphrase = b'xxOzP0PWu21L4a78W6DB'
client_secret = 'MlLYG0kPTrjYhEEbCuLgYDKOKusHfrZlSiGE0YmhRIj8PD1qYJnV6yLQA-jFt8mj4p-pzsQONCfGMI_bLLnFgg'
client_id = '1c60eb45-3801-47ab-8b4e-fe2c4d5a8da6'
redirect_uri = 'http://localhost'

login_url = 'https://federation.basf.com/nidp/app/login?id=CYT'
authz_url = 'https://federation-qa.basf.com/nidp/oauth/nam/authz?client_id=' + client_id + '&redirect_uri=' + redirect_uri + '&scope=apim&acr_values=Cert/Yes/Terminal'
token_url = 'https://federation-qa.basf.com/nidp/oauth/nam/token'

with pfx_to_pem(cert_pfx, cert_passphrase) as cert:
    # Login Endpoint
    response_login = requests.get(login_url, cert=cert)

    # Authz Endpoint
    response_authz = requests.get(authz_url, cert=cert, cookies=response_login.cookies, allow_redirects=False)
    result = re.search('&code=(.+?)&scope', response_authz.headers['Location'])
    accesstoken = result.group(1)

    # Token Endpoint
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'code': accesstoken, 'grant_type': 'authorization_code', "redirect_uri": redirect_uri,
               'client_secret': client_secret, 'client_id': client_id, 'resourceServer': 'Unencrypted'}
    token_response = requests.post(token_url, headers=headers, data=payload)
    access_token = json.loads(token_response.text)['access_token']

print(access_token)


