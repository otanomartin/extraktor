import contextlib
import tempfile
import requests
import re
import json
import os
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import PublicFormat
from requests.exceptions import RequestException

@contextlib.contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    ''' Decrypts the .pfx file to be used with requests. '''
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as t_pem:
        with open(pfx_path, 'rb') as pfx_file:
            pfx_data = pfx_file.read()
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            pfx_data, pfx_password.encode()
        )
        # Write private key
        t_pem.write(private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        ))
        # Write certificate
        t_pem.write(certificate.public_bytes(Encoding.PEM))
        # Write additional certificates (if any)
        if additional_certificates:
            for cert in additional_certificates:
                t_pem.write(cert.public_bytes(Encoding.PEM))
        t_pem.close()
        yield t_pem.name

# Load sensitive data from environment variables
cert_pfx = './Certificate.p12'
cert_passphrase = 'xxOzP0PWu21L4a78W6DB'
client_secret = 'MlLYG0kPTrjYhEEbCuLgYDKOKusHfrZlSiGE0YmhRIj8PD1qYJnV6yLQA-jFt8mj4p-pzsQONCfGMI_bLLnFgg'
client_id = '1c60eb45-3801-47ab-8b4e-fe2c4d5a8da6'
redirect_uri = 'http://localhost'

login_url = 'https://federation.basf.com/nidp/app/login?id=CYT'
authz_url = f'https://federation-qa.basf.com/nidp/oauth/nam/authz?client_id={client_id}&redirect_uri={redirect_uri}&scope=profile%clientid'
token_url = 'https://federation-qa.basf.com/nidp/oauth/nam/token'

try:
    with pfx_to_pem(cert_pfx, cert_passphrase) as cert:
        # Login Endpoint
        response_login = requests.get(login_url, cert=cert)
        response_login.raise_for_status()

        # Authz Endpoint
        response_authz = requests.get(authz_url, cert=cert, cookies=response_login.cookies, allow_redirects=False)
        response_authz.raise_for_status()

        if 'Location' not in response_authz.headers:
            raise ValueError("Authorization response missing 'Location' header.")

        result = re.search(r'&code=([^&]+)&scope', response_authz.headers['Location'])
        if not result:
            raise ValueError("Access token not found in authorization response.")
        accesstoken = result.group(1)

        # Token Endpoint
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {
            'code': accesstoken,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'client_secret': client_secret,
            'client_id': client_id,
            'resourceServer': 'Unencrypted'
        }
        token_response = requests.post(token_url, headers=headers, data=payload)
        token_response.raise_for_status()

        access_token = json.loads(token_response.text).get('access_token')
        if not access_token:
            raise ValueError("Access token not found in token response.")

        print("Access token retrieved successfully.")
except RequestException as e:
    print(f"HTTP request failed: {e}")
except Exception as e:
    print(f"An error occurred: {e}")