FROM php:8.3-apache

COPY docker-entrypoint.sh /usr/local/bin/cert-entrypoint.sh
RUN chmod +x /usr/local/bin/cert-entrypoint.sh \
    && sed -i 's/\r$//' /usr/local/bin/cert-entrypoint.sh

COPY src/ /var/www/src/
COPY public/ /var/www/html/

ENV CERTS_DIR=/proxy/certs \
    DYNAMIC_DIR=/proxy/dynamic \
    DYNAMIC_FILE=custom-certificates.yaml

ENTRYPOINT ["cert-entrypoint.sh"]
CMD ["apache2-foreground"]
