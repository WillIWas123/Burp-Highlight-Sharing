FROM golang:latest

WORKDIR /app/
COPY . /app/
#RUN go build /app/
CMD go run /app/main.go -host :8000 -db "root:SecretRootPasswordForDbWhichMayOrMayNotBeGuessable@(db:3306)/highlightSharing"
#CMD /app/Burp-Highlight-Sharing-Server -host :8080 -db "mysql://root:SecretPasswordForDbWhichMayOrMayNotBeGuessable@db/highlightSharing"

