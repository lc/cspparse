# cspparse

## Description

cspparse is a tool to evaluate Content Security Policies. It uses Google's API to retrieve the CSP Headers and returns them in [ReconJSON](https://github.com/ReconJSON/ReconJSON) format. Not only does it check for headers with Google's API, it also parses the target site's HTML to look for any CSP rules that are specified in the `<meta>` tag

## Installation

### Install Command and Download Source With Go Get

```cspparse``` command will be installed to ```$GOPATH/bin``` and the source code (from ```https://github.com/C0RB3N/cspparse```) will be found in ```$GOPATH/src/github.com/C0RB3N/cspparse``` with:

```bash

~ ❯ go get -u https://github.com/C0RB3N/cspparse

```

### Install from Github Source

```bash

~ ❯ git clone https://github.com/C0RB3N/cspparse
~ ❯ cd cspparse
~ ❯ chmod +x install.sh && ./install.sh

```

## Usage

```bash

~ ❯ cspparse <domain / url>

```

### Example

```bash

~ ❯ cspparse https://www.facebook.com

```
