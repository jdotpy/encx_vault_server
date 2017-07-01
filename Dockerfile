FROM python:3
WORKDIR /usr/src/app
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH $PYTHONPATH:/usr/src/app

COPY requirements.txt /usr/src/app/
COPY manage.py /usr/src/app/
COPY django_server /usr/src/app/django_server/
COPY vault_web /usr/src/app/vault_web/

RUN ls -la /usr/src/app
RUN ls -la /usr/src/app/django_server
RUN ls -la /usr/src/app/vault_web
RUN pip install -r requirements.txt
