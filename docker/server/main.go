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
	Value    string `json:"value"`
	Type string `json:"type"`
	Color   string `json:"color"`
	Comment string `json:"comment"`
	ProjectId int `json:"projectid"`
	ProjectName string `json:"projectname"`
}

type list struct{
	Name string `json:"name"`
}



type client struct {
	con     *websocket.Conn
	user    string
	projectId int
}

func removeClient(user string, projectId int) {
	for i := 0; i < len(clients); i++ {
		if clients[i].user == user && clients[i].projectId == projectId {
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
			continue
		}
		var msg wsmessage
		json.Unmarshal(message, &msg)
		results, err := db.Query("SELECT id from project where name=(?);", &msg.ProjectName)
		for results.Next(){
			err = results.Scan(&msg.ProjectId)
			if err != nil{
				log.Println("Error in position 0")
				log.Println(err)
				continue
                        }
		}
		if msg.Action == "UPDATE" {
			var message wsmessage
			defer removeClient(msg.User, msg.ProjectId)
			client := &client{con: c, user: msg.User, projectId: msg.ProjectId}
			clients = append(clients, client)
			results, err = db.Query("SELECT color, comment, user, type, value from request where user != (?) and projectId = (?);", msg.User, msg.ProjectId)
			if results != nil{
				for results.Next(){
					err = results.Scan(&message.Color, &message.Comment, &message.User, &message.Type, &message.Value)
					if err != nil{
						log.Println("Error in position 1")
						log.Println(err)
						continue
					}
					message.ProjectName = msg.ProjectName
					content, err := json.Marshal(message)
					if err != nil {
						log.Println("Error in position 3")
						log.Println(err)
						continue
					}
					client.con.WriteMessage(mt, content)
				}
				results.Close()
			}
		} else if msg.Action == "CREATE"{
			_, err := db.Query("INSERT into project (name) values (?)", msg.ProjectName)
			if err != nil{
				log.Println("Error in position 3.5")
				log.Println(err)
				continue
			}
		} else if msg.Action == "DELETE"{
			_, err := db.Query("DELETE FROM project where name = (?)", msg.ProjectName)
			if err != nil{
				log.Println("Error in position 3.7")
				log.Println(err)
				continue
			}
		} else if msg.Action == "LIST"{
			var list list
			results, err = db.Query("SELECT name from project;")
			if results != nil{
				for results.Next(){
					err = results.Scan(&list.Name)
					if err != nil{
						log.Println("Error in position 4")
						log.Println(err)
						continue
					}
					content, err := json.Marshal(list)
					if err != nil{
						log.Println("Error in position 5")
						log.Println(err)
						continue
					}
					c.WriteMessage(mt, content)
				}
				results.Close()
			}

		} else{
			insert, err := db.Query("INSERT into request (user, projectId, type, value, color, comment) VALUES (?,?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE user=(?), projectId=(?), type=(?), value=(?), color=(?), comment=(?);", msg.User, msg.ProjectId, msg.Type,msg.Value, msg.Color, msg.Comment, msg.User, msg.ProjectId, msg.Type, msg.Value, msg.Color, msg.Comment) // Could probably be handled better
			if err != nil {
				log.Println("Error in position 7")
				log.Println(err)
				continue
			}
			insert.Close()
			for i := 0; i < len(clients); i++ {
				if clients[i].user != msg.User && clients[i].projectId == msg.ProjectId {
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
	create, err := db.Query("CREATE TABLE IF NOT EXISTS project (id int not null auto_increment, name varchar(50) not null unique,primary key(id));")
        if err != nil {
                log.Fatal(err)
        }
        create.Close()
        create, err = db.Query("CREATE TABLE IF NOT EXISTS request (id int not null auto_increment, projectId int not null, type varchar(50) not null, value varchar(2048) not null, color varchar(10) not null, comment varchar(255) not null, user varchar(20) not null,primary key(id), CONSTRAINT unique_key UNIQUE (type, value)) CHARSET=latin1;") // chose latin1 for now, will have to figure out a solution to the length problem later 
        if err != nil {
                log.Fatal(err)
        }
        create.Close()
	clients = []*client{}
	http.HandleFunc("/", highlightSharing)
	log.Fatal(http.ListenAndServe(host, nil))
}
