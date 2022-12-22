#!/bin/bash

sudo apt-get update -y
sudo apt-get install -y \
    build-essential cmake git \
    libgmp3-dev libprocps-dev python3-markdown libboost-all-dev libssl-dev pkg-config \
    default-jre default-jdk \
    python3-pip

pip3 install angr

git config --global url."https://".insteadOf git:// \
    && git clone https://github.com/akosba/jsnark \
    && cd jsnark \
    && git submodule init && git submodule update \
    && cd libsnark \
    && git submodule init && git submodule update \
    && mkdir build && cd build \
    && cmake -DMULTICORE=ON -DPERFORMANCE=ON .. \
    && make