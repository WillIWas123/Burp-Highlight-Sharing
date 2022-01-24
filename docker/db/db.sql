CREATE DATABASE highlightSharing;
CREATE USER 'root'@'db' IDENTIFIED BY 'SecretRootPasswordForDbWhichMayOrMayNotBeGuessable';
GRANT ALL PRIVILEGES ON highlightSharing.* TO 'root'@'db';
FLUSH PRIVILEGES;


