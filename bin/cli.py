from quickconfig import Configuration
from getpass import getpass
import requests
import argparse

from crypt_server.security import load_rsa_key, write_private_path, make_private_dir
import shutil
import json
import os

DEFAULT_CRYPT_DIR = '~/.crypt'
DEFAULT_CONFIG_PATH = 'config.json'
DEFAULT_KEY_PATH = 'key.pem'
CLI_CONFIG_PATHS = [os.path.join(DEFAULT_CRYPT_DIR, DEFAULT_CONFIG_PATH)]

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
            try:
                self._key = load_rsa_key(self.key_path)
            except Exception as e:
                print('Could not load key at path:', self.key_path)
                raise e

    def _request(self, method, path, **params):
        return self.session.request(method, self.host + path, **params)

    def init_user(self, key_passphrase):
        return self._request('POST', '/init-user', data={'passphrase': key_passphrase}).json()

    def query(self, search):
        return self._request('GET', '/search')

    def get(self, path, extract=None):
        return self._request('POST', '/read')

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
    print(client.query(args.search_text))

def cmd_init(client, args):
    host = 'http://localhost:5000' #input('Enter url of crypt server (e.g. https://crypt-server.google.com): ')
    username = 'kj' #input('Enter user name: ')
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
    new_configuration = {
        'host': client.host,
        'user': client.user,
        'token': response['token'],
    }
    make_private_dir(crypt_dir)
    config_file_path = os.path.join(crypt_dir, DEFAULT_CONFIG_PATH)
    key_file_path = os.path.join(crypt_dir, DEFAULT_KEY_PATH)
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
    parser_query.add_argument('search_text', help='Text filter')
    return parser


CMDS = {
    'init': cmd_init,
    'add': cmd_add,
    'query': cmd_query,
}

if __name__ == '__main__':
    config = Configuration(*CLI_CONFIG_PATHS)
    client = CryptClient(
        config.get('host', 'http://localhost:5000'),
        config.get('user'),
        config.get('token'),
        config.get('key_path'),
    )
    parser = build_cli_parser()
    args = parser.parse_args()

    func = CMDS.get(args.cmd)
    print('Executing', args.cmd)
    try:
        func(client, args)
    except KeyboardInterrupt as e:
        print('stopping')
