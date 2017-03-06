from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA as RSAImpl
from Crypto.Hash import SHA512
from Crypto import Random

import base64
import io
import os
import stat
from uuid import uuid4


def load_rsa_key(path):
    f = open(path, 'r')
    key_contents = f.read()
    key = RSA.importKey(key_contents)
    return key

def generate_uuid():
    return str(uuid4())

def hash(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = SHA512.new()
    h.update(data)
    return h.hexdigest()

def generate_secret_key(length=128):
    random = os.urandom(length)
    key = b64encode(random).decode('utf-8')
    return key

def generate_random_bytes(size=64):
    the_bytes = Random.new().read(size)
    return the_bytes

def to_b64_str(the_bytes, encoding='utf-8'):
    return base64.b64encode(the_bytes).decode(encoding)

def from_b64_str(string, encoding='utf-8'):
    return base64.b64decode(string.encode(encoding))

class AES():
    default_key_size = 16 # In bytes; so 16 is a 128-bit key

    @classmethod
    def generate_key(cls, key_size=None):
        if key_size is None:
            key_size = cls.default_key_size
        key = generate_random_bytes(key_size)
        return base64.b64encode(key)

    def __init__(self, metadata, key=None):
        self.metadata = metadata
        if key is None:
            key = self.generate_key()
        self.set_key(key)

    def set_key(self, key):
        if isinstance(key, str):
            self.key = from_b64_str(key)
        else:
            self.key = key

    def get_key(self):
        return to_b64_str(self.key)

    def encrypt(self, payload):
        iv = generate_random_bytes(AES.block_size)
        self.metadata['scheme'] = self.name
        self.metadata['iv'] = to_b64_str(iv)
        self.metadata['mode'] = 'CFB'
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv)
        ciphertext = self.cipher.encrypt(payload.read())
        return io.BytesIO(ciphertext)

    def decrypt(self, ciphertext):
        iv = from_b64_str(self.metadata['iv'])
        self.cipher = AES.new(self.key, AES.MODE_CFB, iv)
        payload = self.cipher.decrypt(iv + ciphertext.read())
        payload = payload[AES.block_size:]
        return io.BytesIO(payload)

class RSA():
    name = 'RSA'
    cipher_name = 'PKCS#1 v1.5 OAEP'
    default_key_size = 2048

    def __init__(self, metadata, key=None):
        self.metadata = metadata
        self._set_key(key)
        self.cipher = PKCS1_OAEP.new(self.key)

    @classmethod
    def generate_key(cls, size=None):
        if not size:
            size = cls.default_key_size
        new_key = RSAImpl.generate(size)
        exported_obj = new_key.exportKey("PEM")
        return io.BytesIO(exported_obj)

    def get_key(self, passphrase=None):
        exported_key = self.key.exportKey("PEM", passphrase=passphrase).decode('utf-8')
        return exported_key

    def get_public_key(self, with_labels=False):
        public_key = self.key.publickey()
        exported_key = public_key.exportKey("PEM").decode('utf-8')
        return exported_key

    def _set_key(self, key):
        key_bytes = key.read()
        self.key = RSAImpl.importKey(key_bytes)

    def encrypt(self, payload):
        self.payload = self.cipher.encrypt(payload)
        self.metadata['scheme'] = self.name
        self.metadata['cipher'] = self.cipher_name
        return self.payload

    def decrypt(self, ciphertext):
        return self.cipher.decrypt(ciphertext)

PRIVATE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # This is 0o600 in octal
PRIVATE_DIR_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR  # This is 0o700 in octal

def make_private_dir(path):
    os.makedirs(path, mode=PRIVATE_DIR_MODE, exist_ok=False)

def write_private_path(path, contents):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL  # Refer to "man 2 open".

    # For security, remove file with potentially elevated mode
    try:
        os.remove(path)
    except OSError:
        pass

    # Open file descriptor
    umask_original = os.umask(0)
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    finally:
        os.umask(umask_original)

    # Open file handle and write to file
    with os.fdopen(descriptor, 'w') as file_writer:
        file_writer.write(contents)
