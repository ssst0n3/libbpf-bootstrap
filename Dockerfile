FROM ubuntu:24.04 AS base
RUN apt update && apt install -y \
    git \
    build-essential \
    clang \
    libelf1 \
    libelf-dev \
    zlib1g-dev
COPY . /src
WORKDIR /src/examples/c
RUN make