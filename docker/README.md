# Burp-Highlight-Sharing-Server

## About

This is the server for the Highlight-Sharing burp extension, this runs in docker-compose, one docker image for the web server written in go, and one image for the database.

Uses port 8000

communicates over websockets

### How to run

docker-compose up db // wait for this command to finish
docker-compose up app // enjoy
