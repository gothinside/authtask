package main

import (
	"database/sql"
	"net/http"

	"github.com/google/uuid"
)

type User struct {
	UUID  uuid.UUID
	Email string
}

type SessionManager interface {
	CreatePair(http.ResponseWriter, string, uuid.UUID) (*SessionTokenPair, error)
	Refresh(http.ResponseWriter, string, uuid.UUID, string, string) (*SessionTokenPair, error)
	CheckAccessToken(r *http.Request) (string, string, uuid.UUID, error)
}

type UserHandler struct {
	DB      *sql.DB
	Session SessionManager
}

var mockusers = `
	INSERT INTO users(ID, EMAIL) VALUES($1, 'kot_dok@list.ru'), ($2, 'mock_data@mail.ru') ON CONFLICT DO NOTHING;
`

func (u *UserHandler) InsertMockUsers() error {
	id1 := "bb054e96-8735-413b-8214-848bf0e67ee2"
	id2 := uuid.NewString()
	_, err := u.DB.Exec(mockusers, id1, id2)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserHandler) FindUserById(GUID string) (*User, error) {
	user := &User{}
	err := u.DB.QueryRow("SELECT id, email FROM users where id = $1", GUID).Scan(&user.UUID, &user.Email)
	if err != nil {
		return nil, err
	}
	return user, nil
}
