from django.contrib.auth.hashers import make_password, check_password
from django.contrib.postgres.fields import JSONField
from django.conf import settings
from datetime import datetime
from django.db import models

import uuid
import io

class UserManager(models.Manager):
    def new(self, **kwargs):
        kwargs['initialized'] = False
        user = User(**kwargs)
        token = user.regen_token()
        user.save()
        return user, token

class User(models.Model):
    user_name = models.CharField(primary_key=True, max_length=100)
    name = models.CharField(max_length=100, null=True, blank=True)
    public_key = models.TextField()
    token = models.CharField(max_length=128)
    is_admin = models.BooleanField(default=False)
    initialized = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    documents = models.ManyToManyField('Document', through='Sanction')

    objects = UserManager()

    def __str__(self):
        return self.user_name

    def struct(self):
        return {
            'user_name': self.user_name,
            'name': self.name,
            'public_key': self.public_key,
            'initialized': self.initialized,
            'is_admin': self.is_admin,
            'created': str(self.created),
        }


    def regen_token(self):
        token = str(uuid.uuid4())
        self.token = make_password(token)
        return token

    def check_token(self, token):
        return check_password(token, self.token)

    def encrypt(self, payload, encode=False):
        rsa = RSA({}, key=self.public_key)
        encrypted_payload = rsa.encrypt(payload, encode=encode)
        return encrypted_payload

    def can(self, action, obj=None):
        # All Admins can do everything right now
        if self.is_admin:
            return True

        if action == 'query':
            if obj == Document:
                return True
            elif obj == Audit:
                return True

        elif action == 'read':
            if isinstance(obj, Document):
                sanction = obj.sanction_for(self)
                return bool(sanction)

            if obj is User:
                return True

        elif action == 'edit':
            if isinstance(obj, Document):
                sanction = obj.sanction_for(self)
                return sanction and saction.can(action)

        elif action == 'sanction':
            if isinstance(obj, Document):
                sanction = obj.sanction_for(self)
                return sanction and saction.can(action)

        elif action == 'create':
            if obj == User and user.is_admin:
                return True
            elif obj == Document:
                if user.is_admin:
                    return True
                if getattr(settings, 'VAULT_EVERYONE_CREATES', False):
                    return True
            return False

        elif action == 'delete':
            if isinstance(obj, Document):
                sanction = obj.sanction_for(self)
                return sanction and saction.can(action)
            elif isinstance(obj, User):
                return user.is_admin

        return False

class DocumentManager(models.Manager):
    def get_doc(self, user, path, version=None):
        if version:
            query = self.filter(id=version, path=path)
        else:
            query = self.latest_versions(for_user=user).filter(path=path)
        try:
            return query.get()
        except (Document.DoesNotExist, ValueError):
            ## We're catching the UUID parsing error as well, hence the ValueError ##
            return None

    def latest_versions(self, for_user=None):
        latest = self.distinct('path').order_by('path', '-created')
        if for_user:
            latest = self.for_user(for_user, qs=latest)
        return latest

    def for_user(self, user, qs=None):
        if qs is None:
            qs = self.filter()
        if user.is_admin:
            return qs
        return qs.filter(sanctions__user=user)

class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    path = models.CharField(max_length=200)
    encrypted_data = models.BinaryField()
    signature = models.TextField()
    metadata = JSONField()
    created = models.DateTimeField(auto_now_add=True)
    creator = models.ForeignKey(User)

    objects = DocumentManager()

    class Meta:
        index_together = ["path", "created"]

    def __str__(self):
        return '{}::{}'.format(self.path, self.id)

    def sanction_for(self, user):
        try:
            return Sanction.objects.get(document=self, user=user)
        except Sanction.DoesNotExist:
            return None

    def sanction_user(self, user, encrypted_key, key_metadata):
        """ Create a new Sanction to authorize a user for a role on this document """
        return Sanction.objects.create(
            document=self,
            user=user,
            encrypted_key=encrypted_key,
            metadata=key_metadata,
        )

    def struct(self):
        return {
            'id': self.id,
            'path': self.path,
            'metadata': self.metadata,
            'signature': self.signature,
            'creator': str(self.creator),
            'created': str(self.created),
        }

    def audit(self, user, action):
        if getattr(settings, 'VAULT_ENABLE_AUDIT', False):
            Audit.objects.create(
                user_name=user.user_name,
                document_path=self.path,
                document_version=self.id,
                action=action,
            )

class Sanction(models.Model):
    ROLE_OWNER = 'owner'
    ROLE_ADMIN = 'admin'
    ROLE_EDITOR = 'editor'
    ROLE_VIEWER = 'viewer'
    SANCTION_ROLES = (
        (ROLE_OWNER, 'Owner'),
        (ROLE_ADMIN, 'Administrator'),
        (ROLE_EDITOR, 'Editor'),
        (ROLE_VIEWER, 'Viewer'),
    )
    ALL_ROLES = [r[0] for r in SANCTION_ROLES]
    CAN_READ_ROLES = {ROLE_VIEWER, ROLE_EDITOR, ROLE_ADMIN, ROLE_OWNER}
    CAN_EDIT_ROLES = {ROLE_EDITOR, ROLE_ADMIN, ROLE_OWNER}
    CAN_SANCTION_ROLES = {ROLE_ADMIN, ROLE_OWNER}
    CAN_DELETE_ROLES = {ROLE_ADMIN, ROLE_OWNER}

    user = models.ForeignKey(User, related_name='sanctions')
    document = models.ForeignKey(Document, related_name='sanctions')
    encrypted_key = models.TextField()
    metadata = JSONField()

    class Meta:
        unique_together = ('user', 'document')

class Audit(models.Model):
    ACTION_CREATE = 'create'
    ACTION_READ = 'read'
    ACTION_UPDATE = 'update'
    ACTION_DELETE = 'delete'

    AUDIT_ACTIONS = (
        (ACTION_CREATE, 'Created'),
        (ACTION_READ, 'Read'),
        (ACTION_UPDATE, 'Updated'),
        (ACTION_DELETE, 'Deleted'),
    )
    user_name = models.CharField(max_length=100)
    document_path = models.CharField(max_length=200)
    document_version = models.UUIDField()
    action = models.CharField(max_length=100, choices=AUDIT_ACTIONS)
    timestamp = models.DateTimeField(auto_now_add=True)

    def struct(self):
        return {
            'timestamp': str(self.timestamp),
            'action': self.get_action_display(),
            'user_name': self.user_name,
            'document_path': self.document_path,
            'document_version': self.document_version,
        }
