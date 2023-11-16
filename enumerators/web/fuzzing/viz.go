package fuzzing

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

type VisNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type VisEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func sha(input string) string {
	// Here we start with a new hash.
	h := sha256.New()
	h.Write([]byte(input))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func colorFromStatus(status int) string {
	switch status {
	case 200:
		return "green"
	case 301:
		return "blue"
	case 302:
		return "blue"
	default:
		return "red"
	}
}

func convertToDigraph(data map[string]*FuzzTask) string {
	var digraph []string

	// A map to track added nodes: URL -> nodeName
	addedNodes := make(map[string]string)

	// Start the digraph declaration
	digraph = append(digraph, "digraph {")

	// Function to get or create a node name
	getNodeName := func(url string) string {
		if nodeName, exists := addedNodes[url]; exists {
			return nodeName
		}
		nodeName := sha(url)
		addedNodes[url] = nodeName
		digraph = append(digraph, fmt.Sprintf("  %s[label=\"%s\"];", nodeName, url))
		return nodeName
	}

	// Add parent nodes and children nodes
	for _, enumItem := range data {
		parentNodeName := getNodeName(enumItem.Target)

		for _, hit := range enumItem.Hits {
			hitNodeName := getNodeName(hit.Title) // Use the getNodeName function
			digraph = append(digraph, fmt.Sprintf("  %s -> %s[label=\"%s - %d\", color=\"%s\"];", parentNodeName, hitNodeName, enumItem.Type, hit.StatusCode, colorFromStatus(hit.StatusCode)))

			if hit.Redirect != "" {
				redirectNodeName := getNodeName(hit.Redirect) // Use the getNodeName function
				digraph = append(digraph, fmt.Sprintf("  %s -> %s[label=\"redirect\", color=\"%s\"];", hitNodeName, redirectNodeName, colorFromStatus(301)))
			}
		}
	}

	// End the digraph declaration
	digraph = append(digraph, "}")

	return strings.Join(digraph, "\n")
}
