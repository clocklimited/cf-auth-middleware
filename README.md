# cf-auth-middleware

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


An authenticated request contains the following headers:

```
Content-Type: 'application/json'
x-cf-date: 'Tue, 05 Nov 2013 12:22:23 GMT'
authorization: 'Catfish {authorizing entity id}:{signed request}'
```

The client must sign the request with the following algorithm:

```js
var crypto = require('crypto')

function createSignature(key, method, contentType, date, path) {
  var hmac = crypto.createHmac('sha1', key)
    , packet = method + '\n\n' + (contentType || '') + '\n' + date + '\n\n' + path
  return hmac.update(packet).digest('base64')
}
```

## Credits
Built by developers at [Clock](http://clock.co.uk).

## Licence
Licensed under the [New BSD License](http://opensource.org/licenses/bsd-license.php)
