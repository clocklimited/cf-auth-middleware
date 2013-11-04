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

`@todo` explain how the client must sign the request, and what headers are required.

## Credits
Built by developers at [Clock](http://clock.co.uk).

## Licence
Licensed under the [New BSD License](http://opensource.org/licenses/bsd-license.php)
