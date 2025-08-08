FROM httpd:2.4.50

USER root

RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org|archive.debian.org|g' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list

COPY ./httpd.conf /usr/local/apache2/conf/httpd.conf
COPY flag.txt /tmp/flag.txt

# Run installation, flag injection, and cleanup in a single layer
RUN apt-get update && apt-get install -y sed \
    && FLAG_CONTENT=$(cat /tmp/flag.txt) \
    && sed -i "$ a CTF FLAG: ${FLAG_CONTENT}" /etc/passwd \
    && rm /tmp/flag.txt
