package fixtures

import (
	"fmt"
	"log"
)

type DB struct{}
type User struct {
	Name string
}

func (db *DB) FindByID(id int) (*User, error) {
	return nil, fmt.Errorf("not found")
}

// BasicNilDeref demonstrates missing return after error handling.
// GoGuard should flag NIL001 on line where user.Name is accessed.
func BasicNilDeref(db *DB) {
	user, err := db.FindByID(42)
	if err != nil {
		log.Printf("error: %v", err)
		// BUG: missing return — falls through to user.Name
	}
	fmt.Println(user.Name) // NIL001: user may be nil here
}
