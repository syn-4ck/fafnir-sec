FROM  python:3-alpine3.19

ENV VERSION=1.0.0

RUN apk update && apk upgrade

WORKDIR /app

COPY . .

RUN pip install --upgrade pip

RUN pip install wheel
RUN python setup.py bdist_wheel
RUN pip install dist/fafnir-$VERSION-py3-none-any.whl

RUN adduser -D fafnir
USER fafnir
