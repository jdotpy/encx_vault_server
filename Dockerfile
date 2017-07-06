FROM python:3
WORKDIR /usr/src/app
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH $PYTHONPATH:/usr/src/app

ADD requirements.txt /usr/src/app/

VOLUME /usr/src/app

RUN pip install -r requirements.txt
