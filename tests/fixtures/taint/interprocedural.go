package main

import (
	"database/sql"
	"net/http"
)

func processQuery(db *sql.DB, query string) {
	db.Query(query)
}

func handler(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("search")
	db, _ := sql.Open("postgres", "")
	processQuery(db, "SELECT * FROM items WHERE name = '"+userInput+"'")
}

func main() {
	http.HandleFunc("/", handler)
}
