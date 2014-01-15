module.exports = createMiddleware

var parseAuthHeader = require('./header-parser')
  , createSignature = require('cf-signature')

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

    var creds = parseAuthHeader(req)

    if (creds instanceof Error) {
      logger.warn(creds.message)
      return cb(null)
    }

    authProvider.lookupKey(creds.id, function (err, key) {
      if (err) return cb(err)

      var valid = validSignature(req, key, creds.key)

      if (!valid) {
        logger.warn('Unsuccessful authorization', creds)
        logger.debug('Authorization successful:', creds.id)
        return cb(null)
      }

      cb(null, creds.id)

    })

  }

  /*
   * Sign the request and see if it matches the signature
   * the client sent. Returns true if it matches, false if not.
   */
  function validSignature(req, key, theirSig) {

    if (!key) return false

    var contentType = req.headers['content-type'] ? req.headers['content-type'].split(';')[0] : ''
      , ourSig = createSignature(key, req.method, contentType, req.headers['x-cf-date'], req.url)

    logger.debug('Comparing:', ourSig, theirSig)

    return theirSig === ourSig

  }

}