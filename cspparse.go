package main

/*
-====== CSP Parser ======-
by: Corben Leo (https://corben.io)
Contributor(s):
- Riley Johnson (https://therileyjohnson.com)

%% Description:
> Gets Content-Security-Policies for given URL / Domain.
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

// define a map of lists (with type string)
// globally so any function can access it
var cspObject map[string]interface{}

func main() {
	// initialize the cspObject map
	cspObject = make(map[string]interface{})

	// adding objects to the map cspObject, this
	// specific data is to make the output valid ReconJSON
	cspObject["type"] = "ServiceDescriptor"
	cspObject["name"] = "httpCsp"
	cspObject["location"] = "Header"

	// if user passes a command line argument (the domain  / url to check)
	if len(os.Args) > 1 {

		// Set the variable to the first argument passed
		domain := os.Args[1]

		// Validate the given URL
		_, err := url.ParseRequestURI(domain)

		if err != nil {
			fmt.Println("Domain must be a valid URL")
			os.Exit(1)
		}

		// pass the domains to our functions
		err = getCSPApi(domain)

		if err != nil {
		}

		err = getCSPHtml(domain)

		if err != nil {
			fmt.Println(errors.Wrap(err, "No CSP // Could not retrieve CSP Information"))
			os.Exit(1)
		}

		// Pump the map into pretty printed json
		bytes, err := json.MarshalIndent(cspObject, "", "    ")

		if err != nil {
			fmt.Println(errors.Wrap(err, "error formatting output JSON"))
			os.Exit(1)
		}

		// Print it to the user
		fmt.Println(string(bytes))
	} else {
		// if no domain or url is passed show the usage to the user.
		fmt.Println("[+] Usage: cspparse https://www.facebook.com")
	}
}

func getCSPApi(domain string) error {
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
		return errors.New("no CSP for the domain given")
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
func getCSPHtml(domain string) error { // Need to set a timeout because the default request client has none
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get(domain)

	doc, err := goquery.NewDocumentFromReader(resp.Body)

	if err != nil {
		return errors.Wrap(err, "could not parse HTML from domain")
	}

	// Find all <meta> tags to see if there is a CSP
	doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		// Check if <meta> tag has the attribute http-equiv set to "Content-Security-Policy"
		if name, _ := s.Attr("http-equiv"); name == "Content-Security-Policy" {
			// Grab the CSP rule from the "content" attribute
			description, _ := s.Attr("content")

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
	})

	return nil
}
