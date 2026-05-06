package handler

import (
	"net/http"
	"time"
)

// Negative case: this client has Timeout set, missing-timeout must NOT fire here.
var goodClient = &http.Client{
	Timeout: 5 * time.Second,
}

// Negative case: this goroutine has defer recover, panic-in-goroutine must NOT fire here.
func SafeWorker() {
	go func() {
		defer func() {
			_ = recover()
		}()
		// work
	}()
}

// Negative case: error is properly handled.
func handle(w http.ResponseWriter, r *http.Request) {
	resp, err := goodClient.Get("https://example.com")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(http.StatusOK)
}
