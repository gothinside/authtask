package main

import "golang.org/x/crypto/bcrypt"

func HashToken(Token string) string {
	hashToken, _ := bcrypt.GenerateFromPassword([]byte(Token), bcrypt.DefaultCost)
	return string(hashToken)
}

func CheckHash(token string, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(token), []byte(hash))
}
