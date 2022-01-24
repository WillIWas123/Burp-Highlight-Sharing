FROM mysql:latest

VOLUME ["/var/lib/mysql"]

COPY db.sql /docker-entrypoint-initdb.d/schema.sql
