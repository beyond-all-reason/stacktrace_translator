# Use an official PHP image with Apache
FROM php:7.4-apache

# Install any additional system dependencies required for xmlrpc and curl extensions
RUN apt-get update && \
    apt-get install -y libxml2-dev libcurl4-openssl-dev git && \
    rm -rf /var/lib/apt/lists/*

# Install the PHP xmlrpc extension
RUN docker-php-ext-install xmlrpc curl

# Clone the GitHub repository
RUN git clone https://github.com/beyond-all-reason/stacktrace_translator.git /stacktrace_translator

# Copy the frontend files to www
RUN cp -R /stacktrace_translator/php-apache/frontend/* /var/www/html

# Expose port 80
EXPOSE 80