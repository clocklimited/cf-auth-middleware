module.exports = createMiddleware

var crypto = require('crypto')
  , url = require('url')
  , parseAuthHeader = require('./header-parser')

function createMiddleware(authProvider, options) {

  if (!options) options = {}
  var logger = options.logger || console

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

    verify(req, function (err, success) {
      // Don't worry about err, only allow request to complete if success=true
      // otherwise respond with a 401 and authenticate header
      if (success) return next()
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
      return cb(null, false)
    }

    authProvider.lookupKey(creds.id, function (err, key) {
      if (err) return cb(err)

      var valid = validSignature(req, key, creds.key)

      if (valid) {
        logger.debug('Authorization successful:', creds.id)
      } else {
        logger.warn('Unsuccessful authorization', creds)
      }

      return cb(null, valid)

    })

  }

  /*
   * Sign the request and see if it matches the signature
   * the client sent. Returns true if it matches, false if not.
   */
  function validSignature(req, key, sig) {

    if (!key) return false

    var urlParts = url.parse(req.url)
      , hmac = crypto.createHmac('sha1', key)
      , packet = req.method
        + '\n\n' + (req.headers['content-type'] ? req.headers['content-type'].split(';')[0] : '')
        + '\n' + req.headers['x-cf-date'] + '\n\n' + urlParts.pathname
      , hash = hmac.update(packet).digest('base64')

    logger.debug('Comparing:', hash, sig, packet)

    return hash === sig

  }

}