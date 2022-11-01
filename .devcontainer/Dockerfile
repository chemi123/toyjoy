# FROM rust:1.64.0-buster
FROM mcr.microsoft.com/devcontainers/rust:1-bullseye

RUN echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections && \
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

RUN apt update && \
    apt-get -y install iproute2 vim iptables-persistent ethtool tcpdump git zsh screen netcat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
