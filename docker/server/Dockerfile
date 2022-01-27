FROM golang:latest

WORKDIR /app/
COPY . /app/
CMD go run /app/main.go -host :8000 -db "root:SecretRootPasswordForDbWhichMayOrMayNotBeGuessable@(db:3306)/highlightSharing"

