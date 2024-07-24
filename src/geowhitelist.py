from starlette.requests import Request
from starlette.responses import Response

import os
import redis
import ipaddress
import logging
import logging.config
import urllib.parse
from aiohttp import ClientSession
import asyncio
import datetime
import yaml

# Set config paths (should probably turn this into a bootstrap function)
absolutepath = os.path.abspath(__file__)
fileDirectory = os.path.dirname(absolutepath)

if fileDirectory == "/app":
    configDirectory = "/app/config/"
else:
    configDirectory = os.path.dirname(fileDirectory) + "/config"


with open(configDirectory + "/config.yaml", 'r') as config_file:
    config = yaml.safe_load(config_file)

# Default 3h window to keep in Redis
expiry = int(config.get('cache_expiry', 10800))
# Use a different endpoint if you like
serviceURL = config.get('service_url')

# Set Logging config
logging.config.dictConfig(config.get('logging'))

# Setup cache
cache = False
while not cache:
    # Setup Redis cache
    redis_config = config.get('redis')
    if (redis_config and redis_config.get('enabled', False)):
        r = redis.Redis(host=redis_config.get('host', '127.0.0.1'),
                        port=redis_config.get('port', 6379),
                        db=redis_config.get('db', 0),
                        socket_timeout=None)
        try:
            r.ping()
            logging.info("Connected to Redis")
            logging.debug(f"Redis using: {redis_config.get('host')}:\
                {redis_config.get('port')}")
            cache = "redis"
        except Exception:
            logging.error("Redis unreachable, switching to internal cache")
            config['redis']['enabled'] = False
    else:
        internal_cache = set()
        cache = "internal"
        logging.info("Internal Cache set")

# Create whitelist (change to an async function with watchgod)
with open(configDirectory + '/whitelist.yaml', 'r') as f:
    wl_config = yaml.safe_load(f)

wl_ip = set()
wl_cidr = list()
wl_geo = set()

wl_ip_config = wl_config.get('ip')
if wl_ip_config:
    for i in wl_ip_config:
        try:
            if '/' in i:
                wl_cidr.append(ipaddress.ip_network(i))
            else:
                wl_ip.add(ipaddress.ip_address(i))
        except ValueError:
            logging.warning(f"IP address {i} in whitelist is not valid,\
                             skipping")
    logging.debug(f"IP_WL created: \nCIDR:{wl_cidr}\nIP:{wl_ip}")

wl_geo_config = wl_config.get('geo')
if wl_geo_config:
    try:
        # Countries with region set
        wl_geo = set([tuple(i.split('/')) for i in wl_geo_config if '/' in i])
        # Countries with no region set
        o = set([(i, None) for i in wl_geo_config if '/' not in i])
        # Combine sets
        wl_geo.update(o)
        logging.debug(f"Geo whitelist created: {wl_geo}")
    except Exception:
        logging.error("Problem with Geo whitelist config!")
    # Create subset of countries in WL
    wl_country = {i[0] for i in wl_geo}
    logging.debug(f"Countries in WL: {wl_country}")

print('Ready to go')


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    request = Request(scope, receive)

    xff = request.headers['x-forwarded-for']
    decision = await checkIP(xff)
    logging.debug(f"Decision passed as : {decision}")
    if decision is True:
        response = Response('OK', status_code=200, media_type='text/plain')
    else:
        response = Response('FORBIDDEN', status_code=403,
                            media_type='text/plain')
    await response(scope, receive, send)


async def checkIP(ip):
    # Turn address into an address object
    try:
        ipObj = ipaddress.ip_address(ip)
    except ValueError:
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
    # Continue into cache
    else:
        logging.debug(f"Pass {ipObj.compressed} request to accessControl")
        return await accessControl(ipObj)


async def accessControl(ipObj):
    # try IP whitelist (esp for CIDR ranges)
    if await queryIPWL(ipObj):
        return True
    # Not in IP WL's, move to cache
    logging.debug(f"{ipObj.compressed} passed to {cache} cache")
    # cache query (redis)
    if cache == 'redis':
        rq = await redisQuery(ipObj.compressed)
        if rq is not None:
            return rq
    # cache query (internal)
    else:
        iq = await internalQuery(ipObj.compressed)
        if iq is not None:
            return iq
    # geo query
    return await geoQuery(ipObj.compressed)


async def queryIPWL(ipObj):
    # Check if IP in IP WL
    if ipObj in wl_ip:
        logging.info(f"{ipObj.compressed} in WL_IP")
        return True
    # Check if IP in CIDR range WL
    elif any(ipObj in rg for rg in wl_cidr):
        logging.info(f"{ipObj.compressed} in WL_CIDR")
        return True
    # IP Not in either WL, pass along
    else:
        logging.info(f"{ipObj.compressed} not found in IP WL's")
        return False


async def redisQuery(ip):
    # If returns True, Send True(200 OK)
    if r.get(ip) == b'True':
        logging.debug(f"{ip} is TRUE in Redis Cache")
        return True
    # If returns False, send False(403)
    elif r.get(ip) == b'False':
        logging.info(f"{ip} is FALSE in Redis Cache")
        return False
    else:
        logging.debug(f"{ip} not in Redis Cache")
        return None


async def internalQuery(ip):
    match = [c for c in internal_cache if ip in c[0]]
    if match:
        logging.debug(f"{ip} exists in Internal Cache")
        # Pull tuple out of list comprehension from above
        match = match[0]
        # Check if entry has expired
        now = datetime.datetime.now()
        # If expiration is later than now, return True/False value
        if match[1] > now:
            logging.debug(f"{ip} is {match[2]} in Internal Cache")
            return match[2]
        # If expiration is less than or equal to now, remove from cache
        else:
            logging.debug(f"{ip} expired at: {match[1].ctime()}")
            internal_cache.remove(match)
            return None
    # If entry does not exist in cache, pass along
    else:
        logging.debug(f"{ip} not in Internal Cache")
        return None


async def geoQuery(ip):
    try:
        # Get geo dict
        geo = await getGeo(ip)
        logging.debug(f"Geo info found: {geo}")
    except Exception:
        # Unable to get geo info
        logging.error(f"{ip} BLOCK - Unable to get geo info for IP!")
        return cacheAdd(ip, False)
    # If using a geo whitelist
    try:
        # Check if ip in country WL
        if geo['country_code'] in wl_country:
            logging.debug(f"Country Code: {geo['country_code']} found in WL")
            # Create subset of regions for given country in WL
            wl_region = {i[1] for i in wl_geo if i[0] == geo['country_code']
                         and i[1] is not None}
            logging.debug(f"Regions for {geo['country_code']}\
                         in WL: {wl_region}")
            # Check if the country we are checking has a region limitation
            if wl_region:
                try:
                    # Is the request's region in the wl_region WL
                    if geo['region'] in wl_region:
                        logging.info(f"{ip} OK - Region: {geo['region']}\
                                     found in WL")
                        # Request region in WL
                        return cacheAdd(ip, True)
                    else:
                        # Request region not in WL
                        logging.info(f"{ip} BLOCK - in Country WL: \
                            {geo['country_code']} but {geo['region']} \
                            not in WL")
                        return cacheAdd(ip, False)
                except Exception:
                    # No region available in request
                    logging.info(f"{ip} BLOCK - in Country WL: \
                        {geo['country_code']}, but no Region for IP \
                        (region restriction exists)")
                    return cacheAdd(ip, False)
            else:
                # No region limitation listed for Country, request OK
                logging.info(f"{ip} OK - in Country WL: {geo['country_code']},\
                     No Region restriction")
                return cacheAdd(ip, True)
        else:
            # Country Code not in WL
            logging.info(f"{ip} BLOCK - Country code: {geo['country_code']} \
                not in Geo WL")
            return cacheAdd(ip, False)

    except Exception:
        # Reject no country_code found, or problem with wl
        logging.warning(f"{ip} BLOCK - Problem with Geo WL or \
            IP has no Country Code!")
        return cacheAdd(ip, False)


async def getGeo(address):
    """Utilizes geojs.io which currently doesn't have any limits on it and is a
       public API. In the future I might add others as a round-robin situation
       to reduce data sent to a single endpoint.
    """
    # Encode IP (especially v6) into URL
    url = serviceURL + urllib.parse.quote(address)
    logging.debug(f"URL: {url}")
    async with ClientSession() as session:
        async with session.get(url) as response:
            html = await response.json()
    logging.debug(f"Response from geojs.io:\n{html}")
    return html


def cacheAdd(ip, decision):
    if cache == "redis":
        if decision is True:
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
        if decision is True:
            internal_cache.add((ip, exp, True))
            logging.info(f"IP {ip} Whitelisted, added to Internal Cache")
            return True
        else:
            internal_cache.add((ip, exp, False))
            logging.info(f"IP {ip} Blacklisted, adding to Internal Cache")
            return False
