#!/usr/bin/python3

import ipaddress
import getCountryCode as gcc
import redis
import logging

# TODO - For smaller installations, simplify without Redis?
# TODO - What do use to avoid a buildup of queries overloading the system?
# TODO - If a big whitelist of IP's, load into redis beforehand? Persistent?
# TODO - If no 'region' given in response, do a GMaps API call with lat/lon
# TODO - prevent local IP spoofing?
# TODO - add reason for WL/Ban to redis entry?
# TODO - add a way to modify the whitelist on the fly and flush previous entries
# TODO - check that at least 1 WL is available (maybe a file error or otherwise)

logging.basicConfig(level=logging.INFO)

# Setup Redis
r = redis.Redis(host='localhost', port=6379, db=0, password=None, socket_timeout=None)
logging.debug("Redis setup")

# Default 3h window to keep in Redis
expiry = 60 * 180

# Testing purposes
wl_ip = {}
#wl = {("FR", None),("US", "California"),("US", "Oregon")}
wl = {("US", "California"),("US", "Oregon")}


def checkIP(ip):
    # Turn address into an address object
    try:
        ipObj = ipaddress.ip_address(ip)
    except:
        # Not an ip address object!
        logging.critical("Arg passed to method is not an IP!")
        return False
    logging.debug(f"IP obj is {ipObj.compressed}")
    # Allow local addresses
    if ipObj.is_loopback or ipObj.is_private or ipObj.is_link_local:
        logging.info("IP is Loopback, Private, or Link Local")
        return True
    # Block unspecified and multicast
    elif ipObj.is_unspecified or ipObj.is_multicast:
        logging.info("IP is unspecified or multicast")
        return False
    # Continue into redis
    else:
        logging.debug("Pass request to redisQuery")
        return redisQuery(ipObj.compressed)

def redisQuery(ip):
    # Check if IP exists in redis
    if r.exists(ip):
        logging.debug("IP exists in Redis Cache")
        # If returns True, Send True(200 OK)
        if r.get(ip) == b'True':
            logging.info("IP is TRUE in Redis Cache")
            return True
        # If returns False (or anything else), send False(403)
        else:
            logging.info("IP is FALSE in Redis Cache")
            return False

    # If entry does not exist in cache, find IP information, create decision
    else:
        logging.debug("IP not in Redis Cache, pass to WL query")
        return queryWhitelists(ip)

def redisAdd(ip, decision):
    if decision == True:
        logging.info(f"IP {ip} Whitelisted, adding to Redis Cache")
        r.setex(ip, expiry, 'True')
        return True
    else:
        logging.info(f"IP {ip} Blacklisted, adding to Redis Cache")
        r.setex(ip, expiry, 'False')
        return False

def queryWhitelists(ip):
    # Does a wl_ip exist and is the ip in the WL?
    if wl_ip and (ip in wl_ip):
        logging.info("IP WL exists and IP in WL")
        return redisAdd(ip, True)
    # if a WL exists (geo) continue
    elif wl:
        logging.debug("IP not in IP WL, Geo WL exists")
        try:
            geo = gcc.getGeo(ip)
            logging.debug(f"Geo info found: {geo}")
            return geoQuery(geo, ip)
        except:
            # Unable to get geo info
            logging.error("Unable to get geo info!")
            return False
    # If ip not in wl_ip, and no wl (geo) exists, send 403
    else:
        logging.info("IP not in ip_WL, no geo WL exists!")
        return False

def geoQuery(geo, ip):
    # If using a geo whitelist
    try:
        # Create subset of countries in WL (if fails, log parameter error)
        wl_country = {i[0] for i in wl}
        logging.debug(f"Countries in WL: {wl_country}")
        # Check if ip in country WL
        if geo['country_code'] in wl_country:
            logging.info(f"Country Code: {geo['country_code']} found in WL")
            # Create subset of regions in WL
            wl_region = {i[1] for i in wl if i[0] == geo['country_code'] and i[1] != None}
            logging.debug(f"Regions in WL: {wl_region}")
            # Check if the country we are checking has a region limitation
            if wl_region:
                logging.debug("wl_region not a False(Empty) Value")
                try:
                    # Is the request's region in the wl_region WL
                    if geo['region'] in wl_region:
                        logging.info(f"Region: {geo['region']} found in WL")
                        # Reqest region in WL
                        return redisAdd(ip, True)
                    else:
                        # Request region not in WL
                        logging.info("IP in Country WL but Region not in Region WL")
                        return redisAdd(ip, False)
                except:
                    # No region available in request
                    logging.info("IP in Country WL, but no Region given to match Region WL")
                    return redisAdd(ip, False)
            else:
                # No region limitation listed for Country, request OK
                logging.info("IP in Country WL, No Region restriction")
                return redisAdd(ip, True)
        else:
            # Country Code not in WL
            logging.info("IP Country code not in Country WL")
            return redisAdd(ip, False)

    except:
        # Reject no country_code found, or problem with wl
        logging.warning(f"Problem with WL file or {ip} has no Country Code!")
        return redisAdd(ip, False)
