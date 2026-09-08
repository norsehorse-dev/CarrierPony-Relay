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
COPY docker/entrypoint.sh /usr/local/bin/carrierpony-entrypoint
RUN chmod +x /usr/local/bin/carrierpony-entrypoint

ENTRYPOINT ["carrierpony-entrypoint"]
CMD ["apache2-foreground"]
