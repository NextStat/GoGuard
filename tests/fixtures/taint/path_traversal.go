package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("file")
	data, _ := os.ReadFile(path)
	w.Write(data)
}

func main() {
	http.HandleFunc("/", handler)
}
