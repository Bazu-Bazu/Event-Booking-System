package input

type CreateUserInput struct {
	Email    string
	Nickname string
	Password string
}

type UserUpdateInput struct {
	Email    *string
	Nickname *string
	Password *string
}
