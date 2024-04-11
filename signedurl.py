import argparse
import base64
import boto3
from botocore.exceptions import ClientError
from botocore.signers import CloudFrontSigner
from datetime import datetime, timedelta, timezone
import rsa

# Secrets to fetch from AWS Security Manager
KEY_KEY_ID = 'DOCUMENT-SIGNING-KEY-ID'
KEY_PRIVATE_KEY = 'DOCUMENT-SIGNING-PRIVATE-KEY'


def get_secret(secret_key):
   # This code is straight from the AWS console code example except it returns the secret value
   session = boto3.session.Session()
   client = session.client(service_name='secretsmanager')

   try:
       get_secret_value_response = client.get_secret_value(
           SecretId=secret_key
       )
   except ClientError as e:
       if e.response['Error']['Code'] == 'DecryptionFailureException':
           # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
           # Deal with the exception here, and/or rethrow at your discretion.
           raise e
       elif e.response['Error']['Code'] == 'InternalServiceErrorException':
           # An error occurred on the server side.
           # Deal with the exception here, and/or rethrow at your discretion.
           raise e
       elif e.response['Error']['Code'] == 'InvalidParameterException':
           # You provided an invalid value for a parameter.
           # Deal with the exception here, and/or rethrow at your discretion.
           raise e
       elif e.response['Error']['Code'] == 'InvalidRequestException':
           # You provided a parameter value that is not valid for the current state of the resource.
           # Deal with the exception here, and/or rethrow at your discretion.
           raise e
       elif e.response['Error']['Code'] == 'ResourceNotFoundException':
           # We can't find the resource that you asked for.
           # Deal with the exception here, and/or rethrow at your discretion.
           raise e
   else:
       # Decrypts secret using the associated KMS CMK.
       # Depending on whether the secret is a string or binary, one of these fields will be populated.
       if 'SecretString' in get_secret_value_response:
           secret = get_secret_value_response['SecretString']
       else:
           secret = base64.b64decode(
               get_secret_value_response['SecretBinary'])
       return secret


def rsa_signer(message):
   private_key = get_secret(KEY_PRIVATE_KEY)
   return rsa.sign(
       message,
       rsa.PrivateKey.load_pkcs1(private_key.encode('utf8')),
       'SHA-1')  # CloudFront requires SHA-1 hash


def sign_url(url_to_sign, days_valid):
   key_id = get_secret(KEY_KEY_ID)
   cf_signer = CloudFrontSigner(key_id, rsa_signer)
   signed_url = cf_signer.generate_presigned_url(
       url=url_to_sign, date_less_than=datetime.now(timezone.utc) + timedelta(days=days_valid))
   return signed_url


if __name__ == "__main__":
   my_parser = argparse.ArgumentParser(
       description='CloudFront URL Signing Example')
   my_parser.add_argument('URL',
                          metavar='url',
                          type=str,
                          help='url to sign')
   my_parser.add_argument('--days',
                          metavar='days',
                          nargs='?',
                          const=1,
                          type=int,
                          default=1,
                          help='number of days valid, defaults to 1 if not specified')
   args = my_parser.parse_args()
   url_to_sign = args.URL
   days_valid = args.days

   signed_url = sign_url(url_to_sign, days_valid)
   print(signed_url)
   exit(0)
