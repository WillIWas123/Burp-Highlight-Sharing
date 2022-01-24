package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{} // use default options
var clients []*client
var db *sql.DB

type wsmessage struct {
	Action  string `json:"action"`
	User    string `json:"user"`
	Path    string `json:"path"`
	Color   string `json:"color"`
	Comment string `json:"comment"`
	Project string `json:"project"`
}

type client struct {
	con     *websocket.Conn
	user    string
	project string
}

func removeClient(user string, project string) {
	for i := 0; i < len(clients); i++ {
		if clients[i].user == user && clients[i].project == project {
			clients[i] = clients[len(clients)-1]
			clients = clients[:len(clients)-1]
		}
	}

}

func highlightSharing(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			return
		}
		var msg wsmessage

		json.Unmarshal(message, &msg)
		if msg.Action == "UPDATE" {
			defer removeClient(msg.User, msg.Project)
			client := &client{con: c, user: msg.User, project: msg.Project}
			clients = append(clients, client)
			results, err := db.Query("SELECT path, color, comment, user from request where projectName = (?) AND user != (?)", msg.Project, msg.User)
			if err != nil {
				log.Fatal(err)
			}
			for results.Next() {
				var message wsmessage
				err = results.Scan(&message.Path, &message.Color, &message.Comment, &message.User)
				if err != nil {
					log.Fatal(err)
				}
				message.Project = msg.Project
				content, err := json.Marshal(message)
				if err != nil {
					log.Fatal(err)
				}
				client.con.WriteMessage(mt, content)
			}
			results.Close()
		} else {
			insert, err := db.Query("INSERT into request (user, projectName, path, color, comment) VALUES (?,?, ?, ?, ?) ON DUPLICATE KEY UPDATE user=(?), projectName=(?), path=(?), color=(?), comment=(?);", msg.User, msg.Project, msg.Path, msg.Color, msg.Comment, msg.User, msg.Project, msg.Path, msg.Color, msg.Comment)
			if err != nil {
				log.Fatal(err)
			}
			insert.Close()
			for i := 0; i < len(clients); i++ {
				if clients[i].user != msg.User && clients[i].project == msg.Project {
					clients[i].con.WriteMessage(mt, message)
				}
			}

		}
	}
}

func main() {
	var host string
	var dbString string
	flag.StringVar(&host, "host", ":8000", "Specify listening address")
	flag.StringVar(&dbString, "db", "", "Db string")
	flag.Parse()
	if dbString == "" {
		flag.Usage()
		log.Fatal("Please specify a db string")
	}
	var err error
	db, err = sql.Open("mysql", dbString)
	if err != nil {
		log.Fatal(err)
	}
	create, err := db.Query("CREATE TABLE IF NOT EXISTS request (id int not null auto_increment, projectName varchar(255) not null, path varchar(2550) not null, color varchar(10) not null,comment varchar(255) not null,user varchar(255) not null,primary key(id), CONSTRAINT unique_key UNIQUE(path,projectName));")
	if err != nil {
		log.Fatal(err)
	}
	create.Close()
	clients = []*client{}
	http.HandleFunc("/", highlightSharing)
	log.Fatal(http.ListenAndServe(host, nil))
}