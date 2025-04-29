package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

var (
	refreshExpTime = time.Second * 5
	accesExpTime   = 10
)

var (
	ErrNoAuth = errors.New("No session found")
)

type SessionsJWT struct {
	DB                  *sql.DB
	Secret              []byte
	AccessTokenExpTime  time.Duration
	RefreshTokenExpTime time.Duration
}

type SessionTokenPair struct {
	AccessToken  string
	RefreshToken string
}
type SessionAccessJWTClaims struct {
	UUID uuid.UUID `json:"uuid"`
	IP   string    `json:"ip"`
	jwt.StandardClaims
}

func (sm *SessionsJWT) CheckAccessToken(r *http.Request) (string, string, uuid.UUID, error) {
	sessionToken := r.Header.Get("Authorization")
	//check cookies if need
	// if err == http.ErrNoCookie {
	// 	log.Println("CheckSession no cookie")
	// 	return "", "", uuid.UUID{}, ErrNoAuth
	// }

	payload := &SessionAccessJWTClaims{}
	_, err := jwt.ParseWithClaims(sessionToken, payload, sm.parseSecretGetter)
	if payload.Valid() != nil {
		return "", "", uuid.UUID{}, fmt.Errorf("invalid jwt token: %v", err)
	}
	return payload.IP, payload.Id, payload.UUID, nil
}

func (sm *SessionsJWT) parseSecretGetter(token *jwt.Token) (interface{}, error) {
	method, ok := token.Method.(*jwt.SigningMethodHMAC)
	if !ok || method.Alg() != "HS512" {
		return nil, fmt.Errorf("bad sign method")
	}
	return sm.Secret, nil
}

func (sm *SessionsJWT) CheckRereshToken(token string, token_id string) error {
	var val string
	var is_used bool
	var exp_at time.Time
	err := sm.DB.QueryRow("SELECT token_value, is_used, expire_at from RefreshTokens where token_id = $1", token_id).Scan(&val, &is_used, &exp_at)
	if err != nil {
		return err
	}
	//Alternativniy variant
	// h := hmac.New(sha256.New, sm.Secret)
	// data := fmt.Sprintf("%s:%d", payload.Id, refreshExpTime)
	// h.Write([]byte(data))
	// expectedMAC := h.Sum(nil)
	// messegeMAC, err := base64.StdEncoding.DecodeString(refresh_token)
	// if err != nil {
	// 	return nil, fmt.Errorf("cand hex decode token")
	// }
	// if !hmac.Equal(messegeMAC, expectedMAC) {
	// 	return nil, fmt.Errorf("Error")
	// }

	//Mojno proshe cherez unix time i t.d no i reshil tak, potomu shto eto test task
	tn := time.Now().Add(3 * time.Hour)
	if tn.After(exp_at) {
		return fmt.Errorf("Time has come")
	}

	if err = CheckHash(val, token); err != nil || is_used {
		return fmt.Errorf("Error")
	}
	return nil
}

func (sm *SessionsJWT) CreateRefreshToken(token_id string) (string, error) {
	h := hmac.New(sha256.New, sm.Secret)
	data := fmt.Sprintf("%s:%d", token_id, int(refreshExpTime))
	h.Write([]byte(data))

	token := base64.StdEncoding.EncodeToString(h.Sum(nil))

	exp_at := time.Now().Add(sm.RefreshTokenExpTime)
	hashToken := HashToken(token)
	_, err := sm.DB.Exec("INSERT INTO RefreshTokens(token_id, token_value, is_used, expire_at) VALUES($1, $2, false, $3)", token_id, string(hashToken), exp_at)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (sm *SessionsJWT) CreateAccessToken(w http.ResponseWriter, ip string, tokenID string, guid uuid.UUID) string {
	data := SessionAccessJWTClaims{
		UUID: guid,
		IP:   ip,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(sm.AccessTokenExpTime).Unix(),
			IssuedAt:  time.Now().Unix(),
			Id:        tokenID,
		},
	}
	sessVal, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, data).SignedString(sm.Secret)

	cookie := &http.Cookie{
		Name:    "session",
		Value:   sessVal,
		Expires: time.Now().Add(sm.AccessTokenExpTime),
		Path:    "/",
	}
	http.SetCookie(w, cookie)
	return sessVal
}

func (sm *SessionsJWT) CreatePair(w http.ResponseWriter, ip string, guid uuid.UUID) (*SessionTokenPair, error) {
	id := uuid.NewString()
	refreshSessVal, err := sm.CreateRefreshToken(id)
	if err != nil {
		return nil, err
	}

	accessSessVal := sm.CreateAccessToken(w, ip, id, guid)
	return &SessionTokenPair{
		AccessToken:  accessSessVal,
		RefreshToken: refreshSessVal,
	}, nil
}

func (sm *SessionsJWT) Refresh(w http.ResponseWriter, token_id string, guid uuid.UUID, refresh_token, ip string) (*SessionTokenPair, error) {
	err := sm.CheckRereshToken(refresh_token, token_id)
	if err != nil {
		return nil, err
	}
	refresh_tokens, err := sm.CreatePair(w, ip, guid)
	if err != nil {
		return nil, err
	}

	_, err = sm.DB.Exec("UPDATE RefreshTokens SET is_used = true WHERE token_id = $1", token_id)
	if err != nil {
		return nil, err
	}
	return refresh_tokens, nil
}

func NewSessionsJWT(db *sql.DB, secret string, acces_et time.Duration, refresh_et time.Duration) *SessionsJWT {
	return &SessionsJWT{
		DB:                  db,
		Secret:              []byte(secret),
		AccessTokenExpTime:  acces_et,
		RefreshTokenExpTime: refresh_et,
	}
}
