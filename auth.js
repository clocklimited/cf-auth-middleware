module.exports = createMiddleware

module.exports.validSignature = validSignature

var getCredentials = require('./get-credentials')
  , createSignature = require('cf-signature')
  , url = require('url')

function createMiddleware(authProvider, options) {

  if (!options) options = {}
  var logger = options.logger || console
    , reqProperty = options.reqProperty || 'authedClient'

  if (typeof authProvider.authenticate !== 'function') {
    throw new Error('Expecting an authenticate function')
  }

  if (typeof authProvider.lookupKey !== 'function') {
    throw new Error('Expecting a lookupKey function')
  }

  return middleware

  /*
   * The auth checking middleware. Verifies all request methods
   * except for OPTIONS. If verifcation passes, next() is called
   * and the rest of the route handling stack will be executed.
   * If verification fails, the middleware ends the response with
   * a 401 and a header www-authenticate=Catfish.
   */
  function middleware(req, res, next) {

    // Don't auth options, used in CORS preflight
    if (req.method === 'OPTIONS') return next()

    verify(req, function (err, clientId) {
      // Don't worry about err, only allow request to complete if clientId
      // exists otherwise respond with a 401 and authenticate header
      if (clientId) {
        // Attach the authed client's id to req for use further down the stack
        if (reqProperty) req[reqProperty] = clientId
        return next()
      }
      res.header('www-authenticate', 'Catfish')
      return res.send(401)
    })

  }

  /*
   * Verify that the request was signed by an authenticated user.
   */
  function verify(req, cb) {

    var authPacket
      , creds

    try {
      creds = getCredentials(req)
    } catch (e) {
      logger.warn(e.message)
      return cb(null)
    }

    // Get the appropriate authPacket. Either header or querystring.
    if (req.headers.authorization) {
      authPacket =
        { ttl: req.headers['x-cf-ttl' ]
        , date: req.headers['x-cf-date' ] }
    } else {
      authPacket =
        { ttl: req.query['x-cf-ttl' ]
        , date: req.query['x-cf-date' ] }
    }

    authPacket.date = getInt(authPacket.date)

    if (authPacket.date === undefined) {
      logger.warn('Missing x-cf-date')
      return cb(null)
    }

    authPacket.ttl = getInt(authPacket.ttl)

    authProvider.lookupKey(creds.id, function (err, key) {
      if (err) return cb(err)

      var valid = validSignature(req, authPacket, key, creds.signature
        , { logger: logger, ignoreQueryKeys: options.ignoreQueryKeys })

      if (!valid) {
        logger.warn('Unsuccessful authorization', creds)
        logger.debug('Authorization successful:', creds.id)
        return cb(null)
      }

      cb(null, creds.id)

    })

  }

  function getInt(val) {
    if (!isNaN(val)) {
      val = parseInt(val)
    }
    return val
  }

}

/*
 * Sign the request and see if it matches the signature
 * the client sent. Returns true if it matches, false if not.
 */
function validSignature(req, authPacket, key, theirSig, options) {
  options = options || {}

  options.ignoreQueryKeys = options.ignoreQueryKeys || []

  if (!key) return false

  // We use a URL without the auth querystring info for the signature
  var urlParts = url.parse(req.url, true)
  ; delete urlParts.search
  ; delete urlParts.query.authorization
  ; delete urlParts.query['x-cf-date']
  ; delete urlParts.query['x-cf-ttl']

  options.ignoreQueryKeys.forEach(function (key) {
    delete urlParts.query[key]
  })

  var contentType = req.headers['content-type'] ? req.headers['content-type'].split(';')[0] : ''
    , ourSig = createSignature(key, req.method, contentType, authPacket.date, url.format(urlParts), authPacket.ttl)
    , requestDate = (new Date(authPacket.date)).getTime()
    , currentDate = Date.now()
    , difference = Math.abs(currentDate - requestDate)
    , maxDifference = authPacket.ttl || 60000

  options.logger.debug('Comparing:', ourSig, theirSig)
  options.logger.debug('Request Time: ' + requestDate + ' Current Time: ' + currentDate + ' Difference: ' + difference)

  return (theirSig === ourSig) && difference < maxDifference

}
