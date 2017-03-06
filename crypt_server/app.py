from flask import Flask
from mongoengine import connect

from . import views
from . import middleware

connect('crypt-server', host='localhost', port=27017)

app = Flask('crypt-server')

app.before_request(middleware.auth)
app.route('/')(views.home)
app.route('/init-user', methods=['POST'])(views.user_init)
app.route('/new', methods=['POST'])(views.new)
