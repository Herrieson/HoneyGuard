ARG BASE_IMAGE=python:3.10-slim
FROM ${BASE_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git vim \
    && rm -rf /var/lib/apt/lists/*
