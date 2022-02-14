#!/usr/bin/python3

import urllib.request, urllib.parse
import json

# Utilizes geojs.io which currently doesn't have any limits on it and is a
#   public API. In the future I might add others as a round-robbin situation
#   to reduce data sent to a single endpoint.

def getGeo(address):
    # Use a different endpoint if you like
    serviceURL = "https://get.geojs.io/v1/ip/geo/"
    # Encode ip (especially v6) into url
    url = serviceURL + urllib.parse.quote(address)
    # Grab data from URL
    data = urllib.request.urlopen(url)
    # Turn the data into a json (dict)
    rec = json.loads(data.read().decode())
    
    return rec
