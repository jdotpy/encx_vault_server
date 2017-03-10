#!/usr/bin/env python3

from quickconfig import Configuration
from getpass import getpass
import requests
import argparse

from crypt_core.security import (
    RSA, AES, load_rsa_key, write_private_path,
    make_private_dir, from_b64_str, to_b64_str
)
import shutil
import json
import sys
import os

DEFAULT_CRYPT_DIR = '~/.crypt'
DEFAULT_CONFIG_PATH = 'config.json'
DEFAULT_KEY_PATH = 'key.pem'

class CryptClient():
    def __init__(self, host, user, token, key_path=None):
        self.host = host
        self.user = user
        self.token = token
        self.key_path = key_path
        self.session = requests.Session()
        self.session.headers = {
            'X-CRYPT-USER': self.user,
            'X-CRYPT-TOKEN': self.token,
        }

    @property
    def key(self):
        if not hasattr(self, '_key'):
            passphrase = getpass('Enter passphrase for key {}: '.format(self.key_path))
            try:
                self._key = load_rsa_key(self.key_path, passphrase=passphrase)
            except Exception as e:
                print('Could not load key at path:', self.key_path)
                raise e
        return self._key

    def _request(self, method, path, **params):
        try:
            response = self.session.request(method, self.host + path, **params)
        except Exception as e:
            print('Error! Communication with server failed! {}'.format(str(e)))
            sys.exit(1)
        try:
            data = response.json()
        except ValueError as e:
            print('Error! Unable to parse response from server! {}'.format(str(e)))
            sys.exit(1)

        if str(response.status_code).startswith('4'):
            print('Your bad... {}'.format(data['message']))
            sys.exit(1)


    def init_user(self, key_passphrase):
        return self._request('POST', '/init-user', data={'passphrase': key_passphrase}).json()

    def query(self, search=None):
        return self._request('GET', '/query', params={'q': search}).json()

    def read(self, path, extract=None):
        metadata = self._request('GET', '/document', params={'path': path}).json()
        encrypted_payload = self._request('GET', '/document/data', params={'path': path}).content

        encrypted_key = from_b64_str(metadata['encrypted_key'])
        key = self.key.decrypt(encrypted_key)
        aes = AES(metadata['metadata'], to_b64_str(key))
        payload = aes.decrypt(encrypted_payload).read()
        return payload

    def new(self, path, file_obj):
        return self._request('POST', '/new', files={'file': file_obj}, data={'path': path}).json()

    def update(self, path, data):
        return self._request('POST', '/update')

    def delete(self, path):
        return self._request('DELETE', '/delete')


def cmd_add(client, args):
    body = open(args.file, 'rb')
    print(client.new(args.path, body))

def cmd_query(client, args):
    results = client.query(args.search_term)
    if not results:
        print('No results found!')
        return False

    print('{:<45} | {:<19} | {}'.format('Document', 'Last Modified', 'Version ID'))
    for result in results['documents']:
        print('{:<45} | {:<19} | {}'.format(
            result['path'][:40],
            result['created'][:19],
            result['id'],
        ))

def cmd_read(client, args):
    payload = client.read(args.path)
    try:
        payload = payload.decode('utf-8')
    except ValueError:
        pass
    print(payload)

def cmd_destroy(client, args):
    payload = client.read(args.path)
    try:
        payload = payload.decode('utf-8')
    except ValueError:
        pass
    print(payload)

def cmd_init(client, args):
    host = input('Enter url of crypt server (e.g. https://crypt-server.google.com): ')
    username = input('Enter user name: ')
    token = getpass('Enter user token received during account creation: ')
    key_password = 'foobar' #getpass('Enter a password for your crypt key: ')
    print('Initializing your account....')
    client = CryptClient(host, username, token)
    response = client.init_user(key_password)
    if response['success']:
        print('... done!')
    else:
        print('... Failed to setup account!')
        print('Error: ', response['message'])
        return False
    print('Now, on to configuring the client.')
    crypt_dir = input('Enter a directoy to write crypt key and config to (leave blank for "~/.crypt"): ')
    if not crypt_dir:
        crypt_dir = DEFAULT_CRYPT_DIR
    crypt_dir = os.path.expanduser(crypt_dir)

    if os.path.exists(crypt_dir):
        overwrite_response = input('Crypt directory {} already exists! Overwrite (y/n)?'.format(crypt_dir))
        if overwrite_response not in 'yes':
            print('Aborting')
            return False
        print('Recursively removing', crypt_dir)
        if os.path.isdir(crypt_dir) and not os.path.islink(crypt_dir): # These can both be true
            shutil.rmtree(crypt_dir)
        else:
            os.rm(crypt_dir)

    print('Creating new configuration files...')
    config_file_path = os.path.join(crypt_dir, DEFAULT_CONFIG_PATH)
    key_file_path = os.path.join(crypt_dir, DEFAULT_KEY_PATH)
    new_configuration = {
        'host': client.host,
        'user': client.user,
        'token': response['token'],
        'key_path': key_file_path,
    }
    make_private_dir(crypt_dir)
    print('\tWriting conf file...')
    write_private_path(config_file_path, json.dumps(new_configuration, indent=4))
    print('\t...done.')
    print('\tWriting key file...')
    write_private_path(key_file_path, response['private_key'])
    print('\t...done.')
    print('... done. You\'re all set! Try running "crypt.py query"')


def build_cli_parser():
    parser = argparse.ArgumentParser(prog='crypt-cli')
    subparsers = parser.add_subparsers(help='sub-command help', dest='cmd')

    # Global Options
    parser.add_argument('-c', '--config')

    # Initialize user
    parser_init = subparsers.add_parser('init', help='Initialize a user')
    parser_init.add_argument('-s', '--server')
    parser_init.add_argument('-u', '--username')

    # Add a new file 
    parser_add = subparsers.add_parser('add', help='Add a new file to the crypt')
    parser_add.add_argument('-f', '--file', required=True)
    parser_add.add_argument('-p', '--path', required=True)

    # Query files
    parser_query = subparsers.add_parser('query', help='Query the files in the crypt')
    parser_query.add_argument('search_term', help='Text filter', nargs='?', default=None)

    # Read file
    parser_read = subparsers.add_parser('read', help='Read a file from crypt')
    parser_read.add_argument('path', help='Path of document to read')

    # Sanction user for doc
    parser_sanction = subparsers.add_parser('sanction', help='Give a user access to document')
    parser_sanction.add_argument('path', help='Path of document to grant')
    parser_sanction.add_argument('user', help='Which user to grant access')
    parser_sanction.add_argument('role', help='Role to give user ("owner", "admin", "editor", "viewer")')
    return parser


CMDS = {
    'init': cmd_init,
    'add': cmd_add,
    'query': cmd_query,
    'read': cmd_read,
}

def main():
    parser = build_cli_parser()
    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return False

    func = CMDS.get(args.cmd)

    config = None
    client = None
    if func != 'init':
        if args.config:
            config_path = args.config
        else:
            config_path = os.path.join(DEFAULT_CRYPT_DIR, DEFAULT_CONFIG_PATH)
        config = Configuration(config_path)
        client = CryptClient(
            config.get('host', 'http://localhost:5000'),
            config.get('user'),
            config.get('token'),
            config.get('key_path'),
        )
    try:
        func(client, args)
    except KeyboardInterrupt as e:
        print('stopping')

if __name__ == '__main__':
    main()
