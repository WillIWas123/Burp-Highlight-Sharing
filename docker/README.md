# Burp-Highlight-Sharing-Server

## About

This is the server for the Highlight-Sharing burp extension, this runs with docker-compose, one docker image for the web server written in go, and one image for the database.

Uses port 8000 by default

communicates over websockets

Stores the requests with highlights, comments etc.

Relays highlights to other connected users on the same project

### How to run

docker-compose up db // wait for this command to finish
docker-compose up app // enjoy
