package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{Name: "fortify-sca-client", Version: "1.0.0"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command("./fortify-sca-mcp")}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "check_dependency_policy_compliance",
		Arguments: map[string]any{
			"purl":      "pkg:npm/react@19.1.8",
			"repo_url":  "https://github.com/my-org/my-repo",
			"repo_name": "my-org/my-repo",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, content := range res.Content {
		if t, ok := content.(*mcp.TextContent); ok {
			fmt.Println(t.Text)
		}
	}
}
