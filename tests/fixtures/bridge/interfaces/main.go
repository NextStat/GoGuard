package main

import "fmt"

type Handler interface {
	Handle(event string) error
}

type UserHandler struct{}

func (h *UserHandler) Handle(event string) error {
	fmt.Println("UserHandler:", event)
	return nil
}

type AdminHandler struct{}

func (h *AdminHandler) Handle(event string) error {
	fmt.Println("AdminHandler:", event)
	return nil
}

func ProcessEvent(h Handler, event string) {
	h.Handle(event)
}

func main() {
	ProcessEvent(&UserHandler{}, "login")
	ProcessEvent(&AdminHandler{}, "admin-action")
}
