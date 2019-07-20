FROM mariadb:10.2.17

LABEL description="mariadb-10.2.17-ejbca"

ENV MYSQL_ROOT_PASSWORD=foo123
ENV MYSQL_DATABASE=ejbca
ENV MYSQL_USER=ejbca
ENV MYSQL_PASSWORD=ejbca

# Copy initialization script
# The container executes the script in this folder after MariaDB setup
# COPY ./my-initial.sql /docker-entrypoint-initdb.d/

EXPOSE 3306

CMD ["mysqld"]