# cf-auth-middleware

[![Greenkeeper badge](https://badges.greenkeeper.io/clocklimited/cf-auth-middleware.svg)](https://greenkeeper.io/)

Authentication middleware for APIs using cf-auth-provider

## Installation

    npm install --save cf-auth-middleware

## Usage

```js
var express = require('express')
  , createAuthMiddleware = require('cf-auth-middleware')
  , authProvider = require('cf-auth-provider')(myCollection, hashFn)

var app = express()
  , authMiddleware = createAuthMiddleware(authProvider)

app.get('/private', authMiddleware, function (req, res) {
  // This route is only accessible to users that are
  // able to authenticate with the given authProvider
})
```

An authenticated request must contain either the following headers:

```
Content-Type: 'application/json'
x-cf-date: 'Tue, 05 Nov 2013 12:22:23 GMT'
authorization: 'Catfish {authorizing entity id}:{signed request}'
```

***OR***

It must contain the following query string keys:

```
?authorization={authorizing entity id}:{signed request}&x-cf-date=1423481045233
```

You can also specifiy a custom TTL for the request. This can be sent in either the headers or the query string:

```
Content-Type: 'application/json'
x-cf-date: 'Tue, 05 Nov 2013 12:22:23 GMT'
x-cf-ttl: '120000'
authorization: 'Catfish {authorizing entity id}:{signed request}'
```

```
?authorization={authorizing entity id}:{signed request}&x-cf-date=1423481045233&x-cf-ttl=120000
```

The client must sign requests with the [cf-signature](https://github.com/clocklimited/cf-signature) module.

## API

### var createMiddleware = require('cf-auth-middleware')

### var middleware = createMiddleware(AuthProvider: authProvider, Object: options)

`authProvider` is an instance of `cf-auth-provider`.

Options:

- `options.logger`: an object with `debug()`, `info()`, `warn()`, `error()`. Defaults to `console`.
- `options.reqProperty`: the authed client's id is stored on the request object: `req[options.reqProperty]`. Defaults to `authedClient`.
- `options.ignoreQueryKeys`: an array of keys to ignore when comparing the request to the signature.
This is useful when requests get augmented by unknown cache-busting values. Defaults to `[]`.

## Credits
Built by developers at [Clock](http://clock.co.uk).

## Licence
Licensed under the [New BSD License](http://opensource.org/licenses/bsd-license.php)
