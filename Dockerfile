# The login verifier is a small Go program. It is built here from verifier/ so
# the image never depends on a binary from somewhere else.
FROM golang:1.23 AS verifier
WORKDIR /src
COPY verifier/ .
RUN CGO_ENABLED=0 go build -trimpath -o /cp-verify ./cmd/cp-verify

FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends gnupg \
    && docker-php-ext-install pdo_mysql \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Serve from public/ and let its .htaccess rewrite reach index.php.
RUN sed -ri 's!DocumentRoot /var/www/html!DocumentRoot /var/www/html/public!' /etc/apache2/sites-available/000-default.conf \
    && sed -ri 's!<Directory /var/www/>!<Directory /var/www/html/public>!' /etc/apache2/apache2.conf \
    && sed -ri 's!AllowOverride None!AllowOverride All!' /etc/apache2/apache2.conf

COPY . /var/www/html
COPY --from=verifier /cp-verify /usr/local/bin/cp-verify
COPY docker/entrypoint.sh /usr/local/bin/carrierpony-entrypoint
RUN chmod +x /usr/local/bin/carrierpony-entrypoint

ENTRYPOINT ["carrierpony-entrypoint"]
CMD ["apache2-foreground"]
