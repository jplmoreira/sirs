import os

CENTRAL_HOST = "localhost"
CENTRAL_PORT = 9999

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a30sirs'