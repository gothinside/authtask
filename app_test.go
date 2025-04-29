package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

// Alter - mock_db
var (
	ts     = httptest.NewServer(srv)
	jar, _ = cookiejar.New(nil)
	client = &http.Client{Timeout: 10 * time.Second, Jar: jar}
	url    = ts.URL + "/?guid=bb054e96-8735-413b-8214-848bf0e67ee2"
	srv    = GetApp("user=postgres password=123 dbname=test_db", 1*time.Second, 2*time.Second)
)

func TestApp(t *testing.T) {
	req, _ := http.NewRequest("GET", url, nil)
	res, err := client.Do(req)

	if err != nil {
		fmt.Println(err)
	}
	refresh, _ := io.ReadAll(res.Body)
	tokens := &SessionTokenPair{}
	json.Unmarshal(refresh, &tokens)

	for _, val := range res.Cookies() {
		fmt.Println(val.Value)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/refresh", bytes.NewReader([]byte(tokens.RefreshToken)))
	res, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
}

func TestGUIDError(t *testing.T) {
	req, _ := http.NewRequest("GET", ts.URL+"/?guid=0c7d8190-081b-4962-b1df-7a29c78b80", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 404 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 404, res.StatusCode)
	}
}

func TestAccessToken(t *testing.T) {
	req, _ := http.NewRequest("GET", url, nil)
	res, err := client.Do(req)

	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 200, res.StatusCode)
	}
}

func TestRefreshToken(t *testing.T) {
	ts := httptest.NewServer(srv)
	req, _ := http.NewRequest("GET", url, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 404, res.StatusCode)
	}

	refresh, _ := io.ReadAll(res.Body)
	tokens := &SessionTokenPair{}
	json.Unmarshal(refresh, &tokens)

	req, _ = http.NewRequest("POST", ts.URL+"/refresh", bytes.NewReader([]byte(tokens.RefreshToken)))
	req.Header.Add("Authorization", tokens.AccessToken)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 200, res.StatusCode)
	}
}

func TestRefreshTokenExpTime(t *testing.T) {
	ts := httptest.NewServer(srv)
	req, _ := http.NewRequest("GET", url, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 404, res.StatusCode)
	}

	refresh, _ := io.ReadAll(res.Body)
	tokens := &SessionTokenPair{}
	json.Unmarshal(refresh, &tokens)
	time.Sleep(2 * time.Second)

	req, _ = http.NewRequest("POST", ts.URL+"/refresh", bytes.NewReader([]byte(tokens.RefreshToken)))
	req.Header.Add("Authorization", tokens.AccessToken)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 400 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 400, res.StatusCode)
	}
}

func TestFakeRefreshToken(t *testing.T) {
	ts := httptest.NewServer(srv)
	req, _ := http.NewRequest("GET", url, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	refresh, _ := io.ReadAll(res.Body)
	tokens := &SessionTokenPair{}
	json.Unmarshal(refresh, &tokens)

	req, _ = http.NewRequest("POST", ts.URL+"/refresh", bytes.NewReader([]byte(tokens.RefreshToken+"1")))
	req.Header.Add("Authorization", tokens.AccessToken)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 400 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 400, res.StatusCode)
	}
}

func TestRefreshTokenUsing2Times(t *testing.T) {
	ts := httptest.NewServer(srv)

	req, _ := http.NewRequest("GET", url, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 400, res.StatusCode)
	}

	refresh, _ := io.ReadAll(res.Body)
	tokens := &SessionTokenPair{}
	json.Unmarshal(refresh, &tokens)

	req, _ = http.NewRequest("POST", ts.URL+"/refresh", bytes.NewReader([]byte(tokens.RefreshToken)))
	req.Header.Add("Authorization", tokens.AccessToken)
	res, err = client.Do(req)

	req, _ = http.NewRequest("POST", ts.URL+"/refresh", bytes.NewReader([]byte(tokens.RefreshToken)))
	req.Header.Add("Authorization", tokens.AccessToken)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 400 {
		t.Fatalf("Wrong status code, expected = %d, got = %d", 400, res.StatusCode)
	}
}

func test(t *testing.T) {
	ts.Close()
	t.Run("Test", TestApp)
}
