package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("id")
	db, _ := sql.Open("postgres", "")
	db.Query("SELECT * FROM users WHERE id = " + userID)
}

func main() {
	http.HandleFunc("/", handler)
}
