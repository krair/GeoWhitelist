from starlette.requests import Request
from starlette.responses import Response

import redis
import ipaddress
import configparser
import logging, logging.config
import urllib.parse
from aiohttp import ClientSession
import asyncio
import uvicorn
import datetime

# TODO - For smaller installations, simplify without Redis?
# TODO - add time element for whitelist (-1 forever, or 1 day for ex)

# TODO - What do use to avoid a buildup of queries overloading the system?
# TODO - If a big whitelist of IP's, load into redis beforehand? Persistent?
# TODO - prevent IP spoofing?
# TODO - add reason for WL/Ban to redis entry?
# TODO - check that at least 1 WL is available (maybe a file error or otherwise)

# TODO - LATER -If no 'region' given in response, do a GMaps API call with lat/lon

config = configparser.ConfigParser()
with open('./config/config.ini','r') as config_file:
    config.read_file(config_file)

# Default 3h window to keep in Redis
expiry = config['Default']['cache.expiry']
#host = config['Default']['host']
#port = config['Default']['port']
#workers = config['Default']['workers']

# Set Logging config
logging.config.fileConfig(config)

# Setup cache
cache = False
while not cache:
    # Setup Redis cache
    if config['Redis'].getboolean('redis'):
        r = redis.Redis(host=config['Redis']['redis.host'], \
                    port=config['Redis']['redis.port'], \
                    db=config['Redis']['redis.db'], \
#                    password=config['Redis']['redis.password'], \
                    socket_timeout=None)
        try:
            r.ping()
            logging.info("Connected to Redis")
            logging.debug(f"Redis using: {config['Redis']['redis.host']}:{config['Redis']['redis.port']}")
            cache = "redis"
        except:
            logging.error("Redis unreachable, switching to internal cache")
            config['Redis']['redis'] = 'False'
    else:
        interal_cache = set()
        cache = "internal"

# Create whitelist (change to an async function with watchgod)
wl_config = configparser.ConfigParser()
with open('./config/whitelist.ini','r') as config_file:
    wl_config.read_file(config_file)

wl_ip = set()
wl_cidr = list()
wl_geo = set()

if wl_config['IP'].values():
    wl_config_ip = [v.split() for v in wl_config['IP'].values()][0]
    for i in wl_config_ip:
        try:
            if '/' in i:
                wl_cidr.append(ipaddress.ip_network(i))
            else:
                wl_ip.add(ipaddress.ip_address(i))
        except:
            logging.warning(f"IP address {i} in whitelist is not valid, skipping")
    logging.debug(f"IP_WL created: \nCIDR:{wl_cidr}\nIP:{wl_ip}")

if wl_config['Geo'].values():
    # Pull values out of configparser
    wl_config_geo = [v.split() for v in wl_config['Geo'].values()][0]
    try:
        # Countries with region set
        wl_geo = set([tuple(i.split('/')) for i in wl_config_geo if '/' in i])
        # Countries with no region set
        o = set([(i,None) for i in wl_config_geo if '/' not in i])
        # Combine sets
        wl_geo.update(o)
        logging.debug(f"Geo whitelist created: {wl_geo}")
    except:
        logging.error("Problem with Geo whitelist config!")

print('Ready to go')

async def app(scope, receive, send):
    assert scope['type'] == 'http'
    request = Request(scope, receive)

    xff = request.headers['x-forwarded-for']
    decision = await checkIP(xff)
    logging.debug(f"Decision passed as : {decision}")
    if decision == True:
        response = Response('OK', status_code=200, media_type='text/plain')
    else:
        response = Response('FORBIDDEN', status_code=403, media_type='text/plain')
    await response(scope, receive, send)

async def getGeo(address):
    """Utilizes geojs.io which currently doesn't have any limits on it and is a
       public API. In the future I might add others as a round-robbin situation
       to reduce data sent to a single endpoint.
    """
    # Use a different endpoint if you like
    serviceURL = "https://get.geojs.io/v1/ip/geo/"
    # Encode ip (especially v6) into url
    url = serviceURL + urllib.parse.quote(address)

    async with ClientSession() as session:
        async with session.get(url) as response:

            html = await response.json()
    return html

async def checkIP(ip):
    # Turn address into an address object
    try:
        ipObj = ipaddress.ip_address(ip)
    except:
        # Not an ip address object!
        logging.critical(f"{ip} passed to method is not an IP!")
        return False
    logging.debug(f"IP obj is {ipObj.compressed}")
    # Allow loopback and link-local addresses
    if ipObj.is_loopback or ipObj.is_link_local:
        logging.info(f"{ipObj.compressed} OK - Loopback, or Link Local")
        return True
    # Block unspecified and multicast
    elif ipObj.is_unspecified or ipObj.is_multicast:
        logging.info(f"{ipObj.compressed} BLOCK - unspecified or multicast")
        return False
    # Continue into redis
    else:
        logging.debug(f"Pass {ipObj.compressed} request to redisQuery")
        return await cacheQuery(ipObj)

async def cacheQuery(ipObj):
    if cache == 'redis':
        # Check if IP exists in redis
        if r.exists(ipObj.compressed):
            logging.debug(f"{ipObj.compressed} exists in Redis Cache")
            # If returns True, Send True(200 OK)
            if r.get(ipObj.compressed) == b'True':
                logging.debug(f"{ipObj.compressed} is TRUE in Redis Cache")
                return True
            # If returns False (or anything else), send False(403)
            else:
                logging.info(f"{ipObj.compressed} is FALSE in Redis Cache")
                return False
        else:
            logging.debug(f"{ipObj.compressed} not in Redis Cache, pass to WL query")
            return await queryWhitelists(ipObj)
    else:
        match = [c for c in internal_cache if ipObj.compressed in c[0]]
        if match:
            now = datetime.datetime.now()
            match = match[0]
            logging.debug(f"{ipObj.compressed} exists in Internal Cache")
            # Check if entry has expired
            if match[1] > now:
                internal_cache.remove(match)
            else:
                logging.debug(f"{ipObj.compressed} is {match[2]} in Internal Cache")
                return match[2]
            # If returns True, Send True(200 OK)
            if r.get(ipObj.compressed) == b'True':
                logging.debug(f"{ipObj.compressed} is TRUE in Redis Cache")
                return True
            # If returns False (or anything else), send False(403)
            else:
                logging.info(f"{ipObj.compressed} is FALSE in Redis Cache")
                return False
        # If entry does not exist in cache, find IP information, create decision
        else:
            logging.debug(f"{ipObj.compressed} not in Cache, pass to WL query")
            return await queryWhitelists(ipObj)

async def queryWhitelists(ipObj):
    # Check IP based whitelists
    if ipObj in wl_ip:
        logging.info(f"{ipObj.compressed} in WL_IP")
        return cacheAdd(ipObj.compressed, True)

    elif any(ipObj in rg for rg in wl_cidr):
                logging.info(f"{ipObj.compressed} in WL_CIDR")
                return cacheAdd(ipObj.compressed, True)

    # Try geographical WL
    else:
        try:
            geo = await getGeo(ipObj.compressed)
            logging.debug(f"Geo info found: {geo}")
            return geoQuery(geo, ipObj.compressed)
        except:
            # Unable to get geo info
            logging.error(f"{ipObj.compressed} BLOCK - Unable to get geo info for IP!")
            return cacheAdd({ipObj.compressed}, False)

def geoQuery(geo, ip):
    # If using a geo whitelist
    try:
        # Create subset of countries in WL (if fails, log parameter error)
        wl_country = {i[0] for i in wl_geo}
        logging.debug(f"Countries in WL: {wl_country}")
        # Check if ip in country WL
        if geo['country_code'] in wl_country:
            logging.debug(f"Country Code: {geo['country_code']} found in WL")
            # Create subset of regions in WL
            wl_region = {i[1] for i in wl_geo if i[0] == geo['country_code'] and i[1] != None}
            logging.debug(f"Regions in WL: {wl_region}")
            # Check if the country we are checking has a region limitation
            if wl_region:
                try:
                    # Is the request's region in the wl_region WL
                    if geo['region'] in wl_region:
                        logging.info(f"{ip} OK - Region: {geo['region']} found in WL")
                        # Reqest region in WL
                        return cacheAdd(ip, True)
                    else:
                        # Request region not in WL
                        logging.info(f"{ip} BLOCK - in Country WL: {geo['country_code']} but {geo['region']} not in WL")
                        return cacheAdd(ip, False)
                except:
                    # No region available in request
                    logging.info(f"{ip} BLOCK - in Country WL: {geo['country_code']}, but no Region for IP (region restriction exists)")
                    return cacheAdd(ip, False)
            else:
                # No region limitation listed for Country, request OK
                logging.info(f"{ip} OK - in Country WL: {geo['country_code']}, No Region restriction")
                return cacheAdd(ip, True)
        else:
            # Country Code not in WL
            logging.info(f"{ip} BLOCK - Country code: {geo['country_code']} not in Geo WL")
            return cacheAdd(ip, False)

    except:
        # Reject no country_code found, or problem with wl
        logging.warning(f"{ip} BLOCK - Problem with WL file or IP has no Country Code!")
        return cacheAdd(ip, False)

def cacheAdd(ip, decision):
    if cache == "redis":
        if decision == True:
            logging.info(f"IP {ip} Whitelisted, adding to Redis Cache")
            r.setex(ip, expiry, 'True')
            return True
        else:
            logging.info(f"IP {ip} Blacklisted, adding to Redis Cache")
            r.setex(ip, expiry, 'False')
            return False
    else:
        now = datetime.datetime.now()
        exp = now + datetime.timedelta(seconds=+expiry)
        if decision == True:
            interal_cache.add((ip, exp, 'True'))
            logging.info(f"IP {ip} Whitelisted, added to Internal Cache")
            return True
        else:
            logging.info(f"IP {ip} Blacklisted, adding to Internal Cache")
            internal_cache.add((ip, exp, 'False'))
            return False
