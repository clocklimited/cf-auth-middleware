var crypto = require('crypto')

module.exports = function createSignature(key, method, contentType, date, path) {
  var hmac = crypto.createHmac('sha1', key)
    , packet = method + '\n\n' + (contentType || '') + '\n' + date + '\n\n' + path
  return hmac.update(packet).digest('base64')
}