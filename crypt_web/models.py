from django.contrib.auth.hashers import make_password, check_password
from django.contrib.postgres.fields import JSONField
from django.conf import settings
from datetime import datetime
from django.db import models

from crypt_core.security import generate_uuid, AES, RSA, hasher, to_b64_str, from_b64_str

import uuid
import io


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

    def get_fingerprint(self):
        ## I'd like a more standardized fingerprinting format/source
        ## This should prove unique though
        return hasher(self.public_key)

    def regen_token(self):
        token = generate_uuid()
        self.token = make_password(token)
        return token

    def check_token(self, token):
        return check_password(token, self.token)

    def encrypt(self, raw_payload):
        rsa = RSA({}, key=self.public_key)
        encrypted_payload = rsa.encrypt(raw_payload)
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
                return sanction and saction.can(action)

        elif action == 'edit':
            if isinstance(obj, Document):
                sanction = obj.sanction_for(self)
                return sanction and saction.can(action)

        elif action == 'sanction':
            if isinstance(obj, Document):
                sanction = obj.sanction_for(self)
                return sanction and saction.can(action)

        elif action == 'create':
            if obj == Team and user.is_admin:
                return True
            elif obj == User and user.is_admin:
                return True
            elif obj == Document:
                if user.is_admin:
                    return True
                if getattr(settings, 'CRYPT_EVERYONE_CREATES', False):
                    return True
            return False

        elif action == 'delete':
            if isinstance(obj, Document):
                sanction = obj.sanction_for(self)
                return sanction and saction.can(action)

        return False

class DocumentManager(models.Manager):
    def new(self, creator, path, payload, previous=None):
        new_key = AES.generate_key()
        raw_aes_key = from_b64_str(new_key)
        encryption_metadata = {}
        aes = AES(encryption_metadata, key=new_key)
        encrypted_payload = aes.encrypt(io.BytesIO(payload))

        # Save encrypted data
        doc = Document(
            path=path,
            encrypted_data=encrypted_payload,
            key_fingerprint=hasher(new_key),
            data_fingerprint=hasher(payload),
            metadata=encryption_metadata,
            creator=creator,
        )
        doc.save()

        # Encrypt key with public key of all sanctioned users
        Sanction.objects.create_for_doc(doc, raw_aes_key, previous=previous)
        return doc

    def latest_versions(self, for_user=None):
        latest = self.distinct('path').order_by('path', '-created')
        if for_user:
            latest = self.for_user(for_user, latest)
        return latest

    def for_user(self, user, qs=None):
        if qs is None:
            qs = self.filter()
        if user.is_admin:
            return qs
        return qs.filter(sanction__user=for_user)

    def sanctions_for_update(self):
        """
            One might think this function would just copy the sanctions over
            but we also need to take into account the fact that admin users 
            may have changed.
        """

class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    path = models.CharField(max_length=200)
    encrypted_data = models.BinaryField()
    metadata = JSONField()
    key_fingerprint = models.TextField()
    data_fingerprint = models.TextField()
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

    def struct(self):
        return {
            'id': self.id,
            'path': self.path,
            'metadata': self.metadata,
            'data_fingerprint': self.data_fingerprint,
            'creator': str(self.creator),
            'created': str(self.created),
        }

    def audit(self, user, action):
        if getattr(settings, 'CRYPT_ENABLE_AUDIT', False):
            Audit.objects.create(
                user_name=user.user_name,
                document_path=self.path,
                document_version=self.id,
                action=action,
            )

class Membership(models.Model):
    MEMBERSHIP_ROLES = (
        ('owner', 'Owner'),
        ('admin', 'Administrator'),
        ('user', 'User'),
    )

    user = models.ForeignKey(User)
    team = models.ForeignKey(Team)
    role = models.CharField(max_length=20, choices=MEMBERSHIP_ROLES)

class SanctionManager(models.Manager):
    def create_for_doc(self, doc, key, previous=None):
        """ 
            This creates the sanctions for a newly created document version.
            Automatically adds the owner, any admins. If a doc (presumably the
            previous) is passed in the user roles are copied from it.
        """
        # Start with just the creator of the doc
        user_roles = {doc.creator: Sanction.ROLE_OWNER}

        # Add any admins
        if getattr(settings, 'CRYPT_ADMINS_DECRYPT', False):
            admins = User.objects.filter(is_admin=True)
            for admin in admins:
                user_roles[admin] = Sanction.ROLE_OWNER

        # Copy from previous
        if previous:
            for s in previous.sanctions.all():
                user_roles[s.user] = s.role
        
        # Create the sanctions from user_roles
        for user, role in user_roles.items():
            encrypted_key = to_b64_str(user.encrypt(key))
            Sanction.objects.create(
                document=doc,
                user=user,
                role=role,
                encrypted_key=encrypted_key,
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
    CAN_READ_ROLES = {ROLE_VIEWER, ROLE_EDITOR, ROLE_ADMIN, ROLE_OWNER}
    CAN_EDIT_ROLES = {ROLE_EDITOR, ROLE_ADMIN, ROLE_OWNER}
    CAN_SANCTION_ROLES = {ROLE_ADMIN, ROLE_OWNER}
    CAN_DELETE_ROLES = {ROLE_ADMIN, ROLE_OWNER}

    user = models.ForeignKey(User, related_name='sanctions')
    document = models.ForeignKey(Document, related_name='sanctions')
    role = models.CharField(max_length=20, choices=SANCTION_ROLES, default=ROLE_VIEWER)
    encrypted_key = models.TextField()

    objects = SanctionManager()

    def can(self, action):
        if action == 'read':
            return self.role in self.CAN_READ_ROLES
        elif action == 'edit':
            return self.role in self.CAN_EDIT_ROLES
        elif action == 'sanction':
            return self.role in self.CAN_ADD_SANCTION_ROLES
        elif action == 'delete':
            return self.role in self.CAN_DELETE_ROLES
        return False

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
