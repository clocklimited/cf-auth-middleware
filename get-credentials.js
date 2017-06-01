// Look for valid creds in request. Can be with on querystring or headers,
// but not a mixture. Headers will always override querystring
function getCredentials (req) {
  var header
  var creds

  if (req.headers.authorization) {
    header = req.headers.authorization

    // We only accept Catfish type auth
    var type = header.split(' ')
    if (type[0] !== 'Catfish') throw new Error('Invalid authorization type')

    creds = type[1].split(':')
  } else if (req.query.authorization) {
    creds = req.query.authorization.split(':')
  } else {
    throw new Error('Missing authorization token')
  }

  if (creds.length !== 2) throw new Error('Invalid authorization format')

  return { id: creds[0], signature: creds[1] }
}

module.exports = getCredentials
