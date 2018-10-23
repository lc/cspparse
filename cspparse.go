package main

/*
-====== CSP Parser ======-
by: Corben Leo (https://corben.io)
Contributor(s):
- Riley Johnson (https://therileyjohnson.com)

%% Description:
> Gets Content-Security-Policies for given URLs / Domains
> Output is in ReconJSON (https://github.com/ReconJSON/ReconJSON)
*/

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

func main() {

	// if user passes a command line argument (the domain  / url to check)
	if len(os.Args) > 1 {
		var cspObjectsBytes []byte
		domain := os.Args[1]
		cspObject := make(map[string]interface{})

		// Validate the given URL
		_, err := url.ParseRequestURI(domain)

		if err != nil {
			fmt.Println("Domain must be a valid URL")
			os.Exit(1)
		}

		cspObject, err = getCSPMap(domain)

		if err != nil {
			fmt.Println(errors.Wrap(err, "could not retrieve CSP Information"))
			os.Exit(1)
		}

		// Pump the map into pretty printed json
		cspObjectsBytes, err = json.MarshalIndent(cspObject, "", "    ")

		if err != nil {
			fmt.Println(errors.Wrap(err, "error formatting output JSON"))
			os.Exit(1)
		}

		// Print it to the user
		fmt.Println(string(cspObjectsBytes))
	} else {
		// if no domain or url is passed show the usage to the user.
		fmt.Println("[+] Usage: cspparse https://www.facebook.com")
	}
}

func getCSPApi(domain string, cspObject map[string]interface{}) error {
	// Need to set a timeout because the default request client has none
	client := &http.Client{Timeout: 3 * time.Second}
	requestURL := fmt.Sprintf("https://csp-evaluator.withgoogle.com/getCSP?url=%s", url.QueryEscape(domain))

	// Make a POST request to the endpoint, no content-type nor request body needed
	resp, err := client.Post(requestURL, "", nil)

	if err != nil {
		return errors.Wrap(err, "error making request to csp-evaluator")
	}

	// Defer closing the connection until after we leave the function
	defer resp.Body.Close()

	// create an anonymous struct to marshall the JSON from Google's API
	cspStatus := struct {
		Status string `json:"status"`
		Csp    string `json:"csp"`
	}{}

	// Marshall Google's CSP response JSON into the struct
	err = json.NewDecoder(resp.Body).Decode(&cspStatus)

	if err != nil {
		return errors.Wrap(err, "error decoding response JSON")
	}

	// If Google gave did not give us 'status: "ok"' there is not a CSP
	if cspStatus.Status != "ok" {
		// No CSP for the domain given
		return nil
	}

	// Rules are ';' delimited, split the CSP by ';' into rules
	// occasionally they are delimited by '; ', so we replace it
	catch := strings.Replace(cspStatus.Csp, "; ", ";", -1)
	cspResult := strings.Split(catch, ";")

	for _, result := range cspResult {
		if result != "" {
			// Split the rule by the first space to get valid JSON
			rules := strings.Split(result, " ")

			// ex: default-src * data: blob:; -> "default-src": ["*","data:","blob:"],
			cspObject[rules[0]] = append(make([]string, 0), rules[1:]...)
		}
	}

	return nil
}

func getCSPHtml(domain string, cspObject map[string]interface{}) error {
	// Need to set a timeout because the default request client has none
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get(domain)

	doc, err := goquery.NewDocumentFromReader(resp.Body)

	if err != nil {
		return errors.Wrap(err, "could not parse HTML from domain")
	}

	// Find all '<meta>' tags to see if there is a CSP
	doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		// Check if <meta> tag has the attribute http-equiv set to "Content-Security-Policy"
		if name, _ := s.Attr("http-equiv"); name == "Content-Security-Policy" {
			// Grab the CSP rule from the "content" attribute
			description, exists := s.Attr("content")

			// If the 'content' attr exists on the tag
			if exists {
				// Delete spaces trailing after semicolons before splitting
				delSpace := strings.Replace(description, "; ", ";", -1)

				// Split the CSP into rules by the ; separator
				cspResult := strings.Split(delSpace, ";")

				for _, result := range cspResult {
					if result != "" {
						// Split the rule by the first space to get valid JSON
						rules := strings.Split(result, " ")

						// Ex: default-src * data: blob:; -> "default-src": ["*","data:","blob:"],
						cspObject[rules[0]] = append(make([]string, 0), rules[1:]...)
					}
				}
			}
		}
	})

	return nil
}

func getCSPMap(domain string) (map[string]interface{}, error) {
	// Create the cspObject map
	cspObject := make(map[string]interface{})

	// Adding objects to the map cspObject, this
	// specific data is to make the output valid ReconJSON
	cspObject["type"] = "ServiceDescriptor"
	cspObject["name"] = "httpCsp"
	cspObject["location"] = "Header"

	// Pass the domain and cspObject to our functions
	err := getCSPApi(domain, cspObject)

	if err != nil {
		return nil, errors.Wrapf(err, "could not get CSP information for %s from Google API", domain)
	}

	// Check the domain's HTML for meta tags with more information
	err = getCSPHtml(domain, cspObject)

	if err != nil {
		return nil, errors.Wrapf(err, "could not get CSP information from %s HTML", domain)
	}

	return cspObject, nil
}
