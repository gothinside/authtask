package main

import (
	"crypto/tls"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	gomail "gopkg.in/mail.v2"
)

func send_email_message(to, from, msg, psw string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Your token was refreshed")
	m.SetBody("text/plain", msg)
	d := gomail.NewDialer("smtp.gmail.com", 587, from, psw)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

func GetApp(DBconn string, acces_et time.Duration, refresh_et time.Duration) http.Handler {

	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}

	db, err := sql.Open("postgres", DBconn)
	if err != nil {
		log.Fatalln(err.Error())
	}
	db.Ping()

	sm := NewSessionsJWT(db, os.Getenv("secret"), acces_et, refresh_et)
	u := UserHandler{
		DB:      db,
		Session: sm,
	}
	err = u.InsertMockUsers()
	mux := http.NewServeMux()
	mux.HandleFunc("/", u.Auth)
	mux.HandleFunc("/refresh", u.Refresh)
	return mux
}
