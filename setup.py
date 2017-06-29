from distutils.core import setup
from setuptools import setup, find_packages

setup(
    name = 'vault_web',
    packages=find_packages(),
    version = '0.1.0',
    install_requires=[
        'django',
    ],
    description = 'Server for storing encrypted documents and sharing public keys.',
    author = 'KJ',
    author_email = 'jdotpy@users.noreply.github.com',
    url = 'https://github.com/jdotpy/encx_vault_server',
    download_url = 'https://github.com/jdotpy/vault_server/archive/stable.tar.gz',
    keywords = ['cryptography', 'security', 'cli', 'tools'],
    classifiers = [],
)
