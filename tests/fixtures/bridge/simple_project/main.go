package main

import "fmt"

type User struct {
	Name  string
	Email string
}

func GetUser(id int) (*User, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid id: %d", id)
	}
	return &User{Name: "Alice", Email: "alice@example.com"}, nil
}

func main() {
	user, err := GetUser(1)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(user.Name)
}
