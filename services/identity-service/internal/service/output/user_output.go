package output

import "time"

type UserOutput struct {
	ID        int64
	Email     string
	Nickname  string
	CreatedAt time.Time
}
