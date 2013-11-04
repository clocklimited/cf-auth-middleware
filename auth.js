module.exports = createMiddleware

var crypto = require('crypto')
  , url = require('url')
  , parseAuthHeader = require('./header-parser')

function createMiddleware(authProvider, options) {

  if (!options) options = {}
  var logger = options.logger || console


  return function auth(req, res, next) {

    // Don't auth options, used in CORS preflight
    if (req.method === 'OPTIONS') return next()

    if (typeof authProvider.authenticate !== 'function') {
      throw new Error('Expecting a authenticate function')
    }

    if (typeof authProvider.lookupKey !== 'function') {
      throw new Error('Expecting a lookupKey function')
    }

    verify(req, function (err, success) {
      if (success) return next()
      res.header('www-authenticate', 'Catfish')
      return res.send(401)
    })

  }

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

  function validSignature(req, key, sig) {

    if (!key) return false

    // Added replace charset to fix content-type being different in Firefox for POST requests causing hash !== sig
    var urlParts = url.parse(req.url)
      , hmac = crypto.createHmac('sha1', key)
      , packet = req.method
        + '\n\n' + (req.headers['content-type'] ? req.headers['content-type'].replace('; charset=UTF-8', '') : '')
        + '\n' + req.headers['x-cf-date'] + '\n\n' + urlParts.pathname
      , hash = hmac.update(packet).digest('base64')

    logger.debug('Comparing:', hash, sig, packet)

    return hash === sig

  }

}