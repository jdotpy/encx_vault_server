# Vault Server
 
**Description**: 

This package provides a server intended to be used by the 
[vault CLI tool](https://github.com/jdotpy/encx_vault). 

Please see that repository for further documentation.

  - **Technology stack**: Python 3.4+, Django, PostgreSQL
  - **Status**: Beta
 
## Dependencies

* Python 3.4+
* See requirements.txt
 
## Installation

pip installation can install just the vault_web django app for integration
into the server of your choice. If a whole server is required I recommend 
using the docker-container (#WIP) behind nginx.

	pip install https://github.com/jdotpy/vault_server/archive/stable.tar.gz


Once it is running you will need to run this command to setup the DB: 

	./bin/manage.py migrate

Then to initialize an admin account (Take note of the token!): 

	./bin/manage.py add_vault_admin

Then you're ready to use the client!

## Using Docker

* Install Docker
* Install Docker-compose

	export POSTGRES_PASSWORD="<GENERATE A PASSWORD HERE>"
	export DJANGO_SECRET_KEY="<GENERATE A crytpographically secure message here>"

	docker-compose up

	# While the containers are running ^ 

        docker-compose exec web python manage.py migrate
        docker-compose exec web python manage.py add_vault_admin

	# restart your containers and you're good to go

## How to test the software

	./bin/manage.py test

## Known issues

* Validation is a #WIP
 
## Getting help

Fill out an [issue on github](https://github.com/jdotpy/encx_vault_server/issues) please :)


