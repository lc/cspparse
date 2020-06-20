# cspparse

## Description

cspparse is a tool to evaluate Content Security Policies. It uses Google's API to retrieve the CSP Headers and returns them in [ReconJSON](https://github.com/ReconJSON/ReconJSON) format. Not only does it check for headers with Google's API, it also parses the target site's HTML to look for any CSP rules that are specified in the `<meta>` tag

## Installation

### Install Command and Download Source With Go Get

```cspparse``` command will be installed to ```$GOPATH/bin``` and the source code (from ```https://github.com/lc/cspparse```) will be found in ```$GOPATH/src/github.com/lc/cspparse``` with:

```bash

~ ❯ go get -u github.com/lc/cspparse

```

### Install from Source

```bash

~ ❯ git clone https://github.com/lc/cspparse
~ ❯ cd cspparse
~ ❯ go build 

```

## Usage

```bash

~ ❯ cspparse <domain / url>

```

### Example

```bash

~ ❯ cspparse https://www.facebook.com

```

### Docker

```bash

~ > docker build -t cspparse .
```

Run
```bash

~ > docker run --rm -t cspparse <domain / url>
```


<a href="http://buymeacoff.ee/cdl" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

