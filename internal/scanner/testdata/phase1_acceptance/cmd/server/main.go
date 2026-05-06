package main

import (
	"fmt"
	"net/http"
)

// Defect 1: missing-timeout — http.Client without Timeout field.
// Triggers Phase 1 matcher missing-timeout.
var defaultClient = &http.Client{}

// Defect 2: panic-in-goroutine — goroutine without defer recover.
// Triggers Phase 1 matcher panic-in-goroutine.
func startWorker() {
	go func() {
		panic("boom")
	}()
}

// Defect 3: swallowed-error — error returned but context lost.
// Triggers Phase 1 matcher swallowed-error.
func fetch(url string) []byte {
	resp, err := defaultClient.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body := make([]byte, 0)
	return body
}

func main() {
	startWorker()
	fmt.Println(fetch("https://example.com"))
}
