/*
 * Exporting auth header parsing so that it can be used elsewhere
 */
module.exports = parseAuthHeader

function parseAuthHeader(req) {

  var header = req.headers.authorization

  if (header === undefined) return new Error('Missing authorization header')

  // We only accept Catfish type auth
  var type = header.split(' ')
  if ((type.length !== 2) || (type[0] !== 'Catfish')) return new Error('Invalid authorization type')

  // Get the creds
  var creds = type[1].split(':')
  if (creds.length !== 2) return new Error('Invalid authorization format')

  return { id: creds[0], key: creds[1] }

}