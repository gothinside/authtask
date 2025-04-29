package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func (u *UserHandler) Auth(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		uid := r.URL.Query().Get("guid")
		_, err := u.FindUserById(uid)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		uuid, _ := uuid.Parse(uid)
		tokens, err := u.Session.CreatePair(w, r.RemoteAddr, uuid)
		if err != nil {
			log.Println(err)
		}
		b, _ := json.Marshal(tokens)
		w.Write(b)
	} else {
		http.Error(w, "This method now allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (u *UserHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		refresh, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Refresh token error", http.StatusBadRequest)
			return
		}

		ip, token_id, guid, err := u.Session.CheckAccessToken(r)
		if err != nil {
			http.Error(w, "Acces token error", http.StatusBadRequest)
			return
		}

		tokens, err := u.Session.Refresh(w, token_id, guid, string(refresh), r.RemoteAddr)
		if err != nil {
			http.Error(w, "Refresh token error", http.StatusBadRequest)
			return
		}

		if ip != r.RemoteAddr {
			user, _ := u.FindUserById(guid.String())
			send_email_message(user.Email, os.Getenv("from_email"), fmt.Sprintf("Someone try to refresh your tokens by this ip: %s", ip), os.Getenv("password"))
		}

		b, _ := json.Marshal(tokens)
		w.Write(b)
	} else {
		http.Error(w, "This method now allowed", http.StatusMethodNotAllowed)
		return
	}
}

func main() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}

	connStr := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Print(err.Error())
	}
	db.Ping()

	sm := NewSessionsJWT(db, os.Getenv("secret"), 60*60*24*time.Second, 60*60*24*30*time.Second)
	u := UserHandler{
		DB:      db,
		Session: sm,
	}

	err = u.InsertMockUsers()
	if err != nil {
		log.Println(err)
	}

	http.HandleFunc("/", u.Auth)
	http.HandleFunc("/refresh", u.Refresh)
	http.ListenAndServe(":8080", nil)
}
