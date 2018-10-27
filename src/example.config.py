'''
Created on 13 Aug 2017
@author: cave
Copy this file to config.py and update the settings
'''
#!/usr/bin/env python
# encoding: utf-8

'''
Get your API key
Start by retrieving your API Key from the "Security" section in new Account admin panel to be able to make authenticated requests to the API.
https://account.gandi.net/
'''
api_secret = '---my_secret_API_KEY----'

'''
Gandiv5 LiveDNS API Location
http://doc.livedns.gandi.net/#api-endpoint
https://dns.api.gandi.net/api/v5/
'''
api_endpoint = 'https://dns.api.gandi.net/api/v5'

#your domains with their subdomains in the zone file/UUID 
#tip: subdomain "@" for root of tld
domains = {
  'mydomain1.tld': ["subdomain1", "subdomain2", "subdomain3"],
  'mydomain2.tld': ["subdomain1", "subdomain2"]
}


#300 seconds = 5 minutes
ttl = '300'

#request timeout
timeout=5
retries=3
backoff_factor=0.3

''' 
IP address lookup service 
run your own external IP provider:
+ https://github.com/mpolden/ipd
+ <?php $ip = $_SERVER['REMOTE_ADDR']; ?>
  <?php print $ip; ?>
e.g. 
+ https://ifconfig.co/ip
+ http://ifconfig.me/ip
+ http://whatismyip.akamai.com/
+ http://ipinfo.io/ip
+ many more ...

ifconfig4 should return an IPV4 address
+ https://v4.ident.me
ifconfig6 should return an IPV6 address
+ https://v6.ident.me

or leave either one empty to ignore IPV4 or IPV6
'''
ifconfig4 = 'choose_from_above_or_run_your_own'
ifconfig6 = ''
