# Elevator pitch

NX is a spin-off of [VX](https://github.com/maddsua/vx-proxy) that used proxying-tables over REST instead of RADIUS protocol.

## Proxy protocols

### SOCKS 5

Features:
- ✅ CONNECT command
- ⏳ BIND command
- ⏳ ASSOCIATE command
- ⏳ UDP proxy
- ✅ IPv4/IPV6/DOMAIN address type support
- ✅ Password auth

### HTTP

Features:
- ✅ HTTP tunnelling
- ✅ Forward-proxying
- ✅ Basic proxy auth (username/password)

## Installing

A binary Debian package is available in [Releases](https://github.com/maddsua/nx-proxy/releases).

Building from source is also possible at any point. I mean, it's just a go package after all.

To avoid having to mess with network addresses in docker it's recommended to install NX directly to a host system.

## Configuration

Since the whole point of this thing is to avoid having to manually configure instances - all the service options are provided via the API.

In order to authenticate an instance against your backend you must pass `AUTH_URL` and `SECRET_TOKEN` to one of the config locations, such as `/etc/nx-proxy/nx-proxy.conf`.

A sample config file would look like this:

```env
SECRET_TOKEN=<YOUR_BASE64_ENCODED_TOKEN_HERE>
AUTH_URL=<YOUR_BACKEND_URL_AND_PATH_PREFIX>
# optional debug flag
# WARNING: it causes the logs to be pretty flooded!
# DEBUG=true
```

Important note: URL's support path prefixes. For instance, if your auth endpoint is located at `https://backend.myapp.local/api/rest/v1/proxytables/` - this is exactly what your `AUTH_URL` should look like. All the necessary paths would be appended to this base url.
