# TODO For CDN_Lookup
This is the list of things/plans I'd like to implement to potentially make this thing more extensible for implementing in other ways.

### Ideas
* Break things into modules (similar to cogs in discord bots)
* This does not feel like an extensive list for querying CDN data, so find more ways to fingerprint a website.
* Make the querying of websites more stable. Somtimes websites like to deny queries which could cause errors when running this library. Will need to implement better error handling.
* Find a decent way to implement Rapid7's Sonar data set. Censys.io has limits on the amount of queries one can make in a month.
* Add more CDN's to the list. *(Note: I know over time with new ones being activated and older ones being retired, the list could get bloated. However, I feel keeping the older ones **just in case** could still be useful for random domains.)*
