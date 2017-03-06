import mongoengine as db
from datetime import datetime

from .security import generate_uuid

class User(db.Document):
    user_name = db.StringField(primary_key=True, max_length=100)
    public_key = db.StringField()
    token = db.StringField()
    is_admin = db.BooleanField(default=False)
    initialized = db.BooleanField(default=False)
    created = db.DateTimeField(default=datetime.now)

    def regen_token(self):
        self.token = generate_uuid()
        return self.token

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
