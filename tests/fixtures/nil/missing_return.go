package fixtures

import (
	"fmt"
	"net/http"
)

type OrderService struct{}
type Order struct {
	ID    int
	Total float64
}

func (s *OrderService) GetOrder(id int) (*Order, error) {
	return nil, fmt.Errorf("order %d not found", id)
}

// MissingReturnAfterHTTPError demonstrates the common pattern
// of forgetting return after http.Error.
func MissingReturnAfterHTTPError(w http.ResponseWriter, r *http.Request) {
	svc := &OrderService{}
	order, err := svc.GetOrder(123)
	if err != nil {
		http.Error(w, "order not found", http.StatusNotFound)
		// BUG: missing return
	}
	// NIL003: order may be nil because error was not properly handled
	fmt.Fprintf(w, "Order total: %.2f", order.Total)
}
