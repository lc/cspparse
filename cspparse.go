package main

/*
-====== CSP Parser ======-
by: Corben Leo (https://corben.io)
Contributor(s):
- Riley Johnson (http://therileyjohnson.com)

%% Description:
> Gets Content-Security-Policies for given URL / Domain.
> Output is in ReconJSON (https://github.com/ReconJSON/ReconJSON)
*/

import (
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type cspStatus struct {
	Status string `json:"status"`
	Csp    string `json:"csp"`
}

var cspObject map[string][]string

func main() {
	cspObject = make(map[string][]string)
	cspObject["type"] = append(make([]string, 0), "ServiceDescriptor")
	cspObject["name"] = append(make([]string, 0), "Content-Security-Policy")
	cspObject["location"] = append(make([]string, 0), "Header")
	if len(os.Args) > 1 {
		domain := os.Args[1]
		getCSPApi(domain)
		getCSPHtml(domain)
		bytes, _ := json.MarshalIndent(cspObject, "", "    ")
		fmt.Println(string(bytes))
	} else {
		fmt.Println("[+] Usage: cspparse https://www.facebook.com")
	}
}

func getCSPApi(domain string) string {
	params := req.Param{
		"url": domain,
	}
	url := "https://csp-evaluator.withgoogle.com/getCSP"
	r, err := req.Post(url, params)
	if err != nil {
		fmt.Printf("Error making request:\n%s\n", err)
		os.Exit(1)
	}

	resp := r.Response()
	defer resp.Body.Close()

	var c cspStatus
	err = json.NewDecoder(resp.Body).Decode(&c)

	if err != nil {
		fmt.Printf("Error decoding response JSON:\n%s\n", err)
		os.Exit(1)
	}
	if c.Status == "ok" {
		cspResult := strings.Split(c.Csp, ";")

		for _, result := range cspResult {
			if result != "" {
				rules := strings.Split(result, " ")
				cspObject[rules[0]] = append(make([]string, 0), rules[1:]...)
			}
		}

	}
	return ""
}
func getCSPHtml(domain string) string {
	htmlCode := request(domain)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader((htmlCode)))
	if err != nil {
		log.Fatal(err)
	}
	doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		if name, _ := s.Attr("http-equiv"); name == "Content-Security-Policy" {
			description, _ := s.Attr("content")
			delSpace := strings.Replace(description, "; ", ";", -1)
			cspResult := strings.Split(delSpace, ";")

			for _, result := range cspResult {
				if result != "" {
					rules := strings.Split(result, " ")
					cspObject[rules[0]] = append(make([]string, 0), rules[1:]...)
				}
			}
		}
	})
	return ""
}
func request(url string) string {
	if url != "" {
		r, err := req.Get(url)

		if err != nil {
			fmt.Printf("Error making request:\n%s\n", err)
			os.Exit(1)
		}

		resp := r.Response()
		defer resp.Body.Close()
		bodyBytes, err2 := ioutil.ReadAll(resp.Body)
		if err2 != nil {
			fmt.Printf("Error: %s\n", err2)
		} else {
			bodyString := string(bodyBytes)
			return bodyString
		}
	}
	return ""
}

