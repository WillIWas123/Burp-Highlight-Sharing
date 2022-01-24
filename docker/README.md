# Burp-Highlight-Sharing-Server

## What is this


This is a server for the Highlight-Sharing burp extension, written in go.


## Interesting information

Uses port 8000 by default

communicates over websockets

Stores the requests with highlights, comments etc. in a mysql db

Relays highlights to other connected users on the same project

Does not support SSL yet

Might want to consider changing the passwords before use, to change this you need to change multiple files, grep for Secret, and you'll find it

### How to run

docker-compose up db // wait for this command to finish

docker-compose up app // enjoy
