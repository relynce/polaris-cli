// Package commands — document subcommand.
//
// po-to4az: the J27 journey doc referenced a `rvl document reindex` command
// for triggering re-extraction without curling the pipeline admin endpoint.
// This file implements that command by calling the polaris-side endpoint
// POST /api/documents/{id}/reextract (introduced in po-mp4iq).
package commands

import (
	"fmt"
	"net/http"
	"os"

	"github.com/revelara-ai/rvl-cli/internal/api"
	"github.com/revelara-ai/rvl-cli/internal/config"
)

// CmdDocument dispatches document subcommands.
func CmdDocument(args []string) {
	if len(args) == 0 {
		printDocumentUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "reindex", "reextract":
		cmdDocumentReindex(args[1:])
	case "help", "--help", "-h":
		printDocumentUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown document subcommand: %s\n\n", args[0])
		printDocumentUsage()
		os.Exit(1)
	}
}

func printDocumentUsage() {
	fmt.Println("Usage: rvl document <subcommand> [args]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  reindex <document-id>    Queue a document for re-extraction (knowledge + embeddings)")
	fmt.Println("  reextract <document-id>  Alias for reindex.")
	fmt.Println()
}

func cmdDocumentReindex(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: rvl document reindex <document-id>")
		os.Exit(1)
	}
	docID := args[0]

	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	url := fmt.Sprintf("%s/api/documents/%s/reextract", cfg.APIURL, docID)
	respBody, err := api.MakeAPIRequest(cfg, http.MethodPost, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Re-extract failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Document %s queued for re-extraction.\n", docID)
	if len(respBody) > 0 {
		fmt.Println(string(respBody))
	}
}
