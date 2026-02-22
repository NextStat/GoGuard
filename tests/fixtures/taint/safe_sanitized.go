package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("file")
	cleanPath := filepath.Clean(path)
	data, _ := os.ReadFile(cleanPath)
	w.Write(data)
}

func main() {
	http.HandleFunc("/", handler)
}
