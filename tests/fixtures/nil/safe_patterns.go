package fixtures

import "fmt"

type SafeDB struct{}
type SafeUser struct {
	Name string
}

func (db *SafeDB) FindUser(id int) (*SafeUser, error) {
	return &SafeUser{Name: "test"}, nil
}

// SafeNilCheck — correct error handling pattern.
func SafeNilCheck(db *SafeDB) {
	user, err := db.FindUser(42)
	if err != nil {
		fmt.Println("error:", err)
		return // correctly returns after error
	}
	fmt.Println(user.Name) // safe — error was checked and returned
}

// SafeTypeAssertion — correct comma-ok pattern.
func SafeTypeAssertion(val any) {
	s, ok := val.(string)
	if !ok {
		return
	}
	fmt.Println(s)
}

// SafeMapInit — correctly initialized map.
func SafeMapInit() {
	m := make(map[string]int)
	m["key"] = 42
	fmt.Println(m["key"])
}

// SafeNilCheckInline — inline nil check.
func SafeNilCheckInline(db *SafeDB) string {
	user, err := db.FindUser(1)
	if err != nil {
		return ""
	}
	if user == nil {
		return ""
	}
	return user.Name
}
