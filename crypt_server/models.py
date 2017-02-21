import mongoengine as db
from datetime import datetime

class User(db.Document):
    user_name = db.StringField(max_length=100, required=True, unique=True)
    public_key = db.StringField()
    token = db.StringField()
    is_admin = db.BooleanField(default=False)
    created = db.DateTimeField(default=datetime.now)

class Document(db.Document):
    encrypted_data = db.BinaryField()
    metadata = db.DictField()
    key_fingerprint = db.StringField()
    data_fingerprint = db.StringField()
    path = db.StringField(max_length=200)
    created = db.DateTimeField(default=datetime.now)

class Sanctions(db.Document):
    user = db.ReferenceField('User')
    document = db.ReferenceField('Document')
    encrypted_key = db.StringField()
