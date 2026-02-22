package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	content := template.HTML(name)
	tmpl, _ := template.New("page").Parse("<h1>{{.}}</h1>")
	tmpl.Execute(w, content)
}

func main() {
	http.HandleFunc("/", handler)
}
