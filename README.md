# whatCDN
This is a simple tool "library" which will attempt to harvest/fingerprint CDN data about a
website. 

## How To Setup
Make sure to run `pip3 install -r requirements.txt` before running anything in
the library. 

In the cdn_config.py file, there is two variables you will need to change based
on your registration details from https://censys.io/ which is where one of the
methods in the library uses to collect CDN data. On their API information page,
you will see where to get the UID and SECRET keys from however, it should just
be in your account information. ***Keep in mind, you will only be able to do 250
queries to Censys.io per month with their free plan.*** 

## Implementation
I will demonstrate this using python console:
### Setup Domain Object
```python
>>> from whatCDN.cdn_lookup import *
>>> dom = domain("github.com")
```
### Resolve IP
```python
>>> dom.ip()
```
This will store the IP address which the domain resolves to.
### Find Any CNAME Entries
```python
>>> dom.cname()
```
A CNAME is a resource record in DNS systems which maps one domain to another
(wikipedia). This is the reason we can use this method to check for CDNs as a
domain may be mapped to its CDN provider ergo showing up in the CNAME response.
This may not always be the most accurate method which, as with the rest of
these, are why its checked against the predefined lists.

### Find Nameservers The Domain Uses
```python
>>> dom.namesrv()
```
Find what nameservers a domain may be using. This, in most cases, is not a
definitive clue that the service found is the CDN for the host however, services
like Cloudflare and AmazonDNS can clue in to using CloudFront or Cloudflare.

### Find CDN By HTTPS
```python
>>> dom.https_lookup()
```
This will make a request to the domain and inspect the header of the response
looking for the `server` section. This may reveal potential information of the
server for the domain. 
### Query Censys
```python
>>> dom.censys()
```
We query Censys.io currently for the following header data:
* 443.https.get.headers.server
* 443.https.get.metadata.description
* 443.https.get.headers.vary
* 443.https.get.headers.unknown
* 80.https.get.headers.server
* 80.http.get.headers.vary
* 80.http.get.metadata.description
* 80.http_www.get.headers.unknown
* 80.http_www.get.headers.server 

For the most part, this should cover most of the data which may leak information
about a potential CDN the service is using.

### Comb Through Whois Data
```python
>>> dom.whois()
```
Looks specifically at the \['netowrk'\]\['name'\] section of the response to the
IPwhois module for python. I will probably want to update how it parses the data
received from the IPwhois. An alternative method i thought could happen is doing
an `os.system('whois' + self.dom)` and parse the data off of that. 

### Digest any of the requests
```python
>>> dom.digest()
```
This will go through all of the data collected from all the modules ran and will
parse through them looking for any CDNs which match signatures in cdn_config.py.
Though some may not match, the data does not get removed from all the internal
variables so these can be re-parsed manually if need be.
### Do Everything
```python
>>> dom.all_checks()
```
This does everything mentioned above.
