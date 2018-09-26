# cspparse

## Description
cspparse is a tool to evaluate Content Security Policies. It uses Google's API to retrieve the CSP Headers and returns them in [ReconJSON](https://github.com/ReconJSON/ReconJSON) format. Not only does it check for headers with Google's API, it also parses the target site's HTML to look for any CSP rules that are specified in the `<meta>` tag

## Installation
```
git clone https://github.com/C0RB3N/cspparse
cd cspparse
chmod +x install.sh && ./install.sh
```

## Usage
```
~ ❯ cspparse <domain / url>
```

Example: 

```
~ ❯ cspparse https://www.facebook.com
```
