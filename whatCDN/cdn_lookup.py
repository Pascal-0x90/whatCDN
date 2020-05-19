#!/usr/bin/python3

'''
This script allows a user to tell what cdn that a
website may be using. If no cdn then we will tell
the user there is no cdn. If cdn, we then tell the
user what cdn is being used and return info on the
cdn.
'''
from whatCDN.cdn_config import *
import censys.websites
import urllib.parse as parse
import urllib.request as request
from urllib.error import HTTPError
from dns.resolver import query, NoAnswer, NXDOMAIN, NoNameservers
from ipwhois import IPWhois

DEBUG = False


class domain:
    '''
    Define different sections to store data
    in an object format.
    '''

    def __init__(self, dom):
        self.dom = dom
        self.addr = []
        self.cdn = []
        self.ns = []
        self.cnames = []
        self.censys_data = []
        self.headers = []
        self.whois_data = []
        self.cdn_by_name = []

    '''
    Digest the passed in to the function and
    comb for cdn data and append it to the
    cdn array in the object
    '''

    def cdnDigest(self, setList):
        for dom in setList:
            #print("Checking: %s"%dom)
            for url in CDNs:
                if url.lower().replace(
                        " ", "") in dom.lower().replace(
                        " ", "") and url not in self.cdn:
                    self.cdn.append(url)
                    self.cdn_by_name.append(CDNs[url])
            for name in CDNs_rev:
                if name.lower().replace(
                        " ", "") in dom.lower().replace(
                        " ", "") and CDNs_rev[name] not in self.cdn:
                    self.cdn.append(CDNs_rev[name])
                    self.cdn_by_name.append(name)
            for name in COMMON.keys():
                if name.lower().replace(
                        " ", "") in dom.lower().replace(
                        " ", "") and CDNs_rev[name] not in self.cdn:
                    self.cdn.append(CDNs_rev[name])
                    self.cdn_by_name.append(name)

        # Incase the domain is a CDN
        try:
            for url in CDNs:
                if url.lower().replace(
                        " ", "") in self.dom.lower().replace(
                        " ","") and url not in self.cdn:
                    self.cdn.append(url)
                    self.cdn_by_name.append(CDNs[url])
        except:
            pass

    '''
    Query each section of the object with the
    CDN digest and filter all results into the
    self.cdn list.
    '''

    def digest(self):
        # Check all in Name Servers
        if self.ns is not None:
             self.cdnDigest(self.ns)
        if self.cnames is not None:
            self.cdnDigest(self.cnames)
        if self.censys_data is not None:
            self.cdnDigest(self.censys_data)
        if self.headers is not None:
            self.cdnDigest(self.headers)
        if self.whois_data is not None:
            self.cdnDigest(self.whois_data)
        if self.dom is not None:
            self.cdnDigest(self.dom)

    '''
    Determine any IP addresses the domain resolves to
    '''

    def ip(self):
        # Determine the domain's IP address
        try:
            req = query(self.dom)
        except NXDOMAIN:
            raise NXDOMAIN("Check if %r exists." % self.dom)
        except NoNameservers:
            raise NoNameservers(
                'No Nameservers found for domain: %r' % self.dom)
        except NoAnswer:
            raise NoAnswer('No IP available for domain: %s' % self.dom)
        self.addr = [str(ip.address) for ip in req]

    '''
    When a site is setup on a CDN, such as Amazon Cloudfront or
    CloudFlare, a CNAME record for the domain is setup to point
    at the CDN servers and something similar to a named vhost
    is setup on the CDN web servers so it can respond to the
    request.
    '''

    def cname(self):
        # Check to see if the domain is using a CNAME.
        # This could hint for a CDN, does not exactly mean true
        try:
            req = query(self.dom, 'cname')
            self.cnames = [dom.to_text() for dom in req]
        except NoAnswer as err:
            pass  # print('No CNAME found!',err)
        except NXDOMAIN:
            pass  # print("Error with grabbing %s's cname"%self.dom)

    '''
    With the power of name servers, determine based off of
    name servers the domain is using a potential CDN. This
    will probably not be as accurate but may hint to something.
    '''

    def namesrv(self):
        # Check the NS
        try:
            req = query(self.dom, 'ns')
            self.ns = [url.to_text() for url in req]
            #print('Nameservers: %s'%','.join(self.ns))
        except NoAnswer:
            pass #print("No Nameservers.")
        except NXDOMAIN:
            print("Error with grabbing %s's name servers." % self.dom)
        else:
            pass

    '''
    Query the webserver for the site and observe the
    'server' in the headers of the response to see
    hints if the item is using a CDN or not
    '''

    def https_lookup(self):
        # Observe the header to see if it is a cdn
        try:
            response = request.urlopen("https://" + self.dom)
            self.headers = response.headers['server']
        except HTTPError:
            pass
        #print("Headers: %s"%self.headers)

    '''
    Query censys.io's API to grab any data we may have
    missed from querying the webserver itself
    '''

    def censys(self):
        c = censys.websites.CensysWebsites(UID, SECRET)
        API_FIELDS = ['443.https.get.headers.server',
                      '80.https.get.headers.server',
                      '443.https.get.metadata.description',
                      '443.https.get.headers.vary',
                      '80.http.get.headers.vary',
                      '80.http.get.metadata.description',
                      '80.http_www.get.headers.unknown',
                      '443.https.get.headers.unknown',
                      '80.http_www.get.headers.server']
        data = list(c.search("domain: " + self.dom,
                             API_FIELDS, max_records=10))
        cdns = []
        if len(data) > 0:
            for url in data[0].values():
                if isinstance(url, list):
                    for extra in url:
                        for i in extra.values():
                            cdns.append(i)
                else:
                    cdns.append(url)
        self.censys_data = cdns

    '''
    Make use of whois data about the IP addresses collected
    for the given domain spcified. The org or asn_description
    will give information about who owns the IP addr the
    domain resolves to.
    '''

    def whois(self):
        if self.addr == None or len(self.addr) <= 0:
            self.ip()
        cdn_n = []
        for ip in self.addr:
            op = IPWhois(ip)
            name = op.lookup_rdap()['network']['name']
            for n in COMMON.keys():
                #print("Looking for %s in %s"%(n.lower(),name.lower()))
                if n.lower() in name.lower() != -1 and n not in cdn_n:
                    cdn_n.append(n)
        self.whois_data = cdn_n

    def all_checks(self):
        self.ip()
        self.cname()
        self.namesrv()
        self.https_lookup()
        self.censys()
        self.whois()
        self.digest()
