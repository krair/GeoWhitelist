# GeoWhitelist middleware for Traefik

Traefik ForwardAuth middleware utilizing [GeoJS.io](https://www.geojs.io/) to whitelist IP's based upon geolocation.

## This software *has not* been battle-tested, scrutinized, audited, or checked for vulnerabilities in any way. Use *at your own risk*! I take no responsibility for someone bypassing this simple location-based fence.

## Overview

A small python program that utilizes a user-defined whitelist of countries or country/regions. As IP's attempt to connect to your server, GeoWhitelist can be run as a `forwardAuth` middleware alongside Traefik to authorize or block requests based upon or geolocation or source IP.

When a device attempts to connect, the `X-Forward-For` header will be passed from Traefik to this middleware. The IP is checked against 3 filters:

- Is the IP a legit IP, loopback, link local, not unspecified, or not multicast?
- Does the IP appear in the geographical whitelist?
- Does the IP appear in the provided IP whitelist?

If yes to any of the above, the middlware returns a `status 200 - OK` code, allowing the remote to connect. Otherwise it returns a `status 403 - FORBIDDEN` code, blocking the request and future requests for a period of time. Eventually, the codes could be customized for easier integration with tools like `fail2ban`. Currently you could have `fail2ban` use the Traefik access log to find the `403` codes and ban those as you please.

To hide a service, you could instead return a `404 - Not Found` code.

The decision is stored in either a local cache (non-persistent) or a Redis cache. The default cache time is 3h and can be customized.

If the IP is passed to the geographical lookup, there will be a small delay during the first lookup, but subsequent requests will happen immediately as the decision is served from the cache.

## Prerequisites

- Linux server (tested on CentOS Stream 8, Fedora 35, Ubuntu 20.04)
- Traefik (tested with 2.5+)
- Python3 (tested with 3.6.8+)
- (optional) docker/podman (tested with podman v3.4.1 and v3.4.4)
- (optional) Redis (tested with v6.2)

The app can run with Redis as a caching backend or using an internal Python cache. I haven't done enough extensive testing to see how the performance changes, but generally speaking, Redis is a more robust cache system. For testing or very small deployments, the internal cache should suffice.

**Note:** If the app is unable to reach Redis, it will fall back to the internal cache.

### Redis

If you decide to use a Redis instance, make sure to modify the `config.ini` file to match your Redis settings.

**Note:** I haven't implemented the password setting for Redis yet as I only access it locally.

## Usage

As it's a simple python program using a `uvicorn/gunicorn` server, you could run it directly on your server, or in a container like docker/podman.

### Directly on server

1. Clone this repository:
```
git clone https://github.com/krair/GeoWhitelist
```
2. Install the required python packages:
```
python3 -m pip install -r requirements.txt
```
3. Edit the `config/config.ini` and `config/whitelist.ini` files to your liking.

4. Run with `gunicorn`:
```
gunicorn -b 127.0.0.1:9500 -k uvicorn.workers.UvicornWorker --daemon GeoWhitelist:app
```

This will daemonize the process (run it in the background). Below we will point Traefik at this service.

#### With a Virtual environment

If you don't want to mess with your current version of python or you have multiple versions, consider using a virtual environment. After `pip install`'ing the `requirements.txt` into your `venv` from this repository, run the above command from the virtual environment's directory like:
```
./my-venv/bin/gunicorn -b 127.0.0.1:9500 -k uvicorn.workers.UvicornWorker --daemon GeoWhitelist:app
```

#### As a `systemd` unit

Example:

https://bartsimons.me/gunicorn-as-a-systemd-service/

### Containerized

Generally preferred, and if you are running Traefik via docker/podman anyways, this method is quite easy but will require you to build the container yourself.

**CRITICAL:** If you are running rootless podman, ensure that you are able to get the actual remote address from Traefik and not simply a `10.0.2.100` address. [See below for workaround](#notes-for-podman).

1. Clone this repository:
```
git clone https://github.com/krair/GeoWhitelist
```
2. Edit the `config/config.ini` and `config/whitelist.ini` files to your liking.

3. Build the container:
```
<podman/docker> build -t localhost/geowl .
```

4. Run the container:
**Podman:**
```
<podman/docker> run --name geowl -v ./config:/app/config localhost/geowl
```

**OR**

4. Podman/Docker compose:
```
version: '3.7'
services:
  traefik:
...
  geowl:
    image: localhost/geowl
    container_name: geowl
    volumes:
      - "./config:/app/config"
...
```

**Note:** The above are rough examples and you will have to adjust accordingly, especially for [Podman](#notes-for-podman).

## Connect to Traefik

This component works as a [ForwardAuth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) for Traefik. As such, we will pass all requests through it to make a decision based upon source IP.

This is a very generic example, and if you look at the above link, you can customize the GeoWhitelist middleware to only protect certain URI paths, reqest methods, etc.

**Note:** I have not tested this with other forwardAuth providers such as Authelia, Keycloak, Authentik, etc. I suppose if you were to put this GeoWhitelist middlware in front of those they should still work fine since I don't currently set any cookies or pass headers along. Any testing on this front would be appreciated.

### File Provider

I personally prefer the old fashioned [file provider](https://doc.traefik.io/traefik/providers/file/) for Traefik as it simplifies my compose files. In your dynamic file, it would simply look something like:
```
http:
...
  middlewares:
    geowl:
      forwardAuth:
        address: "http://geowl:9500"
        authRequestHeaders:
          - "X-Forwarded-For"
...
```

And in the router declaration, we add the middleware:
```
http:
...
  routers:
    example-router:
      rule: Host(`example.tld`)
      entryPoints:
        - web
      middlewares:
        - geowl
      service: example
...
```

If Traefik doesn't pick up the changes automatically, you might need to restart your Traefik container.

### Labels

Effectively the same as above, but we can declare the GeoWhitelist middleware with the Traefik container and use it on other services:

```
version: '3.8'
services:
  traefik:
...
    labels:
      - "traefik.http.middlewares.geowl.forwardauth.address=http://geowl:9500"
      - "traefik.http.middlewares.geowl.forwardauth.authRequestHeaders=X-Forwarded-For"
```

And to add the middleware to a container:
```
version: '3.8'
services:
  example:
...
    labels:
      - "traefik.http.routers.example-router.middlewares=geowl"
...
```
## Notes for Podman

### Slirp4netns port handler
If running rootless, the Traefik container must be started with the `--net=slirp4netns:port_handler=slirp4netns` option. If this is not used, it will appear to Traefik (and hence the GeoWhitelist container) that all requests are coming from the local address `10.0.2.100`. [This GitHub question explains some of it](https://github.com/containers/podman/discussions/10472).

Recently Podman 4.0 was released with a new network stack. I have yet to test this.

### Pod-to-pod access

I would recommend running the GeoWhitelist middleware in the same pod as Traefik for simplicity. If you *DO* decide to run in a separate pod, bind it to a local address. For example, create a `dummy` loopback interface bound to an internal address (like `10.254.254.1` for example), and bind your pod to that address. Access it via Traefik using the `10.254.254.1:9500` address.

## Whitelist Usage

### Usage

#### Geolocation

Open your `whitelist.ini` file. Under the `[Geo]` heading there are some examples of how to list locations. Use a new line for each location. To add a whole country, use the [two letter ISO country code](https://www.iso.org/obp/ui/#search) like:
```
DE
```

To add a specific region within a country:
```
FR/Hauts-de-France
```
This can be used multiple times to list more than one region:
```
FR/Hauts-de-France
FR/Île-de-France
```

**Note:** The slash between the country code and the region are critical, as the program splits the line on the `/` instead of a space. This allows us to use region names like `New York`.

If you are unsure of the region name, spelling, etc., it must match the results from [GeoJS.io](https://www.geojs.io/). To check, send a request with the desired IP and have a look at the result. For example with `9.9.9.9`:
```
curl -Ls https://get.geojs.io/v1/ip/geo/9.9.9.9 | tr ',' '\n' | grep region | cut -d ':' -f 2
```
output:
```
"California"
```

##### What if there's no output??

This means there's no region attached to the IP address. See the [Concept](#concept) section below.

#### IP

While this section is a bit repetitive and mimics the [ipWhitelist](https://doc.traefik.io/traefik/middlewares/http/ipwhitelist/) middleware already provided by Traefik, the inclusion was fairly trivial so I added it anyways. I may end up removing it later to simplify the code and just focus on the geolocation feature.

To include an IP, simply add it to your `whitelist.ini` file under the `[IP]` section:
```
192.168.1.14
```

To include a range of IP's, CIDR notation can be used:
```
10.11.12.0/24
```

### Concept
There's still a fair amount of testing I would have to do for more complete documentation for this. But the general concept is that when an IP is sent to the GeoJS endpoint, we have a few fields we can use as filters in our whitelist.

For example, if I ask for details on `9.9.9.9`:
```
curl -L https://get.geojs.io/v1/ip/geo/9.9.9.9
```
output:
```
{"organization_name":"QUAD9-AS-1","region":"California","accuracy":100,"asn":19281,"organization":"AS19281 QUAD9-AS-1","timezone":"America\/Los_Angeles","longitude":"-122.2676","country_code3":"USA","area_code":"0","ip":"9.9.9.9","city":"Berkeley","country":"United States","continent_code":"NA","country_code":"US","latitude":"37.8767"}
```

For now, I have only implemented `country_code` and an optional `region` to the filter. Not all addresses give the region in their response:
```
curl -L https://get.geojs.io/v1/ip/geo/8.8.8.8
```
output:
```
{"organization_name":"GOOGLE","accuracy":1000,"asn":15169,"organization":"AS15169 GOOGLE","timezone":"America\/Chicago","longitude":"-97.822","country_code3":"USA","area_code":"0","ip":"8.8.8.8","country":"United States","continent_code":"NA","country_code":"US","latitude":"37.751"}
```

Therefore, by adding `US/Californa` to our whitelist, would allow `9.9.9.9` and deny `8.8.8.8` from connecting to the server as we have created a restriction for regions. However, if we simply add `US` with no region behind, both would be allowed to connect.

Thus GeoWhitelist is not a perfect solution, but if you are trying to protect a specific service behind Traefik, we generally know where we *want* the access coming from. Most home internet users will have a fairly accurate location attached to their IP.

Can someone get around this by using a VPN masking their IP? Absolutely. This is not meant to be a "silver bullet" for security, just an added layer to remove requests from obvious script kiddies and scanners.

## Support

Any support is appreciated:
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/A0A74AJX7)
