ARG APACHE_VERSION=2.4
FROM httpd:${APACHE_VERSION}

RUN apt-get update && \
    apt-get install -y apache2-dev gcc make curl git

RUN git clone https://github.com/joecorall/apache-antibot /usr/local/src/antibot

WORKDIR /usr/local/src/antibot

RUN git fetch --all && \
    git checkout tags/0.0.3 && \
    apxs -c -i mod_antibot.c && \
    install -c .libs/mod_antibot.so /usr/local/apache2/modules/mod_antibot.so

COPY antibot.conf /etc/apache2/conf.d/antibot.conf
COPY index.html /var/www/html/
RUN echo 'IncludeOptional /etc/apache2/conf.d/antibot.conf' >> /usr/local/apache2/conf/httpd.conf

HEALTHCHECK CMD curl -f http://localhost/
