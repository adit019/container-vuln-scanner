﻿FROM alpine:3.20
RUN adduser -D app
USER app
WORKDIR /app
COPY . /app
