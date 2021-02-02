FROM ubuntu:18.04

ENV DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

RUN apt-get update && apt-get -y install \
    git \
    cmake \
    make \
    gcc \
    g++ \
    flex \
    bison \
    libpcap-dev \
    libssl-dev \
    python3 \
    python3-dev \
    python3-pip\
    swig \
    zlib1g-dev \
    libmaxminddb-dev \
    libkrb5-dev \
    bsdmainutils \
    sqlite3 \
    curl \
    wget \
    unzip \
    ruby \
    bc \
    lcov \
  && rm -rf /var/lib/apt/lists/*

# Install clang-11 for the coverage task
RUN echo "deb http://apt.llvm.org/bionic llvm-toolchain-bionic-11 main" >> /etc/apt/sources.list.d/llvm-11.list
RUN echo "deb-src http://apt.llvm.org/bionic llvm-toolchain-bionic-11 main" >> /etc/apt/sources.list.d/llvm-11.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt-get update && apt-get -y install llvm-11 clang-11 && rm -rf /var/lib/apt/lists/*
RUN ln -s /usr/bin/llvm-cov-11 /usr/bin/llvm-cov

RUN pip3 install junit2html
RUN gem install coveralls-lcov
