package fixtures

import "fmt"

type UserDB struct{}
type UserRecord struct {
	Name  string
	Email string
}

func (db *UserDB) GetUser(id int) (*UserRecord, error) {
	return nil, fmt.Errorf("user %d not found", id)
}

// ErrorIgnored demonstrates dereferencing a value when error is ignored.
func ErrorIgnored(db *UserDB) string {
	user, _ := db.GetUser(42)
	return user.Name // NIL001: user may be nil because error was discarded
}
