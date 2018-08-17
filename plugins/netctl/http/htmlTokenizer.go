//Functions taken from https://schier.co/blog/2015/04/26/a-simple-web-scraper-in-go.html
package http

import (
	"fmt"
	"golang.org/x/net/html"
	"net/http"
	"strings"
)

// Helper function to pull the href attribute from a Token
func getHref(t html.Token) (ok bool, href string) {
	// Iterate over all of the Token's attributes until we find an "href"
	for _, a := range t.Attr {
		if a.Key == "href" {
			href = a.Val
			ok = true
		}
	}

	// "bare" return will return the variables (ok, href) as defined in
	// the function definition
	return
}

//Crawl extracts all http** links from a given webpage
func Crawl(url string) []string {
	resp, err := http.Get("http://" + url)
	urlSlice := make([]string, 0)

	if err != nil {
		fmt.Println("ERROR: Failed to crawl \"" + url + "\"")
		return []string{}
	}

	b := resp.Body
	defer b.Close() // close Body when the function returns

	z := html.NewTokenizer(b)

	for {
		tt := z.Next()

		switch {
		case tt == html.ErrorToken:
			// End of the document, we're done
			return urlSlice
		case tt == html.StartTagToken:
			t := z.Token()

			// Check if the token is an <a> tag
			isAnchor := t.Data == "a"
			if !isAnchor {
				continue
			}

			// Extract the href value, if there is one
			ok, url := getHref(t)
			if !ok {
				continue
			}

			// Make sure the url begines in http**
			hasProto := strings.Index(url, "/vpp/dump/v1/") == 0
			if hasProto {
				urlSlice = append(urlSlice, url)
			}
		}
	}
}
