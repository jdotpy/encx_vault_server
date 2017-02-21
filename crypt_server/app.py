from flask import Flask
from mongoengine import connect

from . import views

connect('crypt-server', host='localhost', port=27017)

app = Flask('crypt-server')

app.route('/')(views.home)
