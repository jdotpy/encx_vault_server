from django.contrib.auth.hashers import make_password, check_password
from django.contrib.postgres.fields import JSONField
from django.db import models
from datetime import datetime
import uuid

from crypt_core.security import generate_uuid

class Team(models.Model):
    team_name = models.CharField(primary_key=True, max_length=100)
    created = models.DateTimeField(auto_now_add=True)
    creator = models.ForeignKey('User')

    def __str__(self):
        return self.team_name

class User(models.Model):
    user_name = models.CharField(primary_key=True, max_length=100)
    public_key = models.TextField()
    token = models.CharField(max_length=128)
    is_admin = models.BooleanField(default=False)
    initialized = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    documents = models.ManyToManyField('Document', through='Sanction')
    teams = models.ManyToManyField('Team', through='Membership')

    def __str__(self):
        return self.user_name

    def regen_token(self):
        token = generate_uuid()
        self.token = make_password(token)
        return token

    def check_token(self, token):
        return check_password(token, self.token)

class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    path = models.CharField(max_length=200)
    encrypted_data = models.BinaryField()
    metadata = JSONField()
    key_fingerprint = models.TextField()
    data_fingerprint = models.TextField()
    created = models.DateTimeField(auto_now_add=True)
    creator = models.ForeignKey(User)

    def __str__(self):
        return '{}::{}'.format(self.path, self.id)

    def struct(self):
        return {
            'id': self.id,
            'path': self.path,
            'metadata': self.metadata,
            'data_fingerprint': self.data_fingerprint,
            'creator': str(self.creator),
            'created': str(self.created),
        }

class Membership(models.Model):
    MEMBERSHIP_ROLES = (
        ('owner', 'Owner'),
        ('admin', 'Administrator'),
        ('user', 'User'),
    )

    user = models.ForeignKey(User)
    team = models.ForeignKey(Team)
    role = models.CharField(max_length=20, choices=MEMBERSHIP_ROLES)

class Sanction(models.Model):
    SANCTION_ROLES = (
        ('owner', 'Owner'),
        ('admin', 'Administrator'),
        ('editor', 'Editor'),
        ('viewer', 'Viewer'),
    )
    user = models.ForeignKey(User)
    document = models.ForeignKey(Document)
    role = models.CharField(max_length=20, choices=SANCTION_ROLES)
    encrypted_key = models.TextField()
