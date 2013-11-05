module.exports = createAuthProvider

var genKey = require('hat')

function createAuthProvider() {

  var sessions = {}

  var users =
    { 'ben.gourley@clock.co.uk': { _id: 'a', password: 'hai' }
    , 'paul.serby@clock.co.uk': { _id: 'b', password: 'face' }
    }

  function lookupKey(id, cb) {
    if (id === 'fail') return cb(new Error('uh oh'))
    cb(null, sessions[id])
  }

  function authenticate(creds, cb) {
    if (!creds.identity) return cb(new Error('Invalid credentials.'))
    if (creds.password !== users[creds.identity].password) return cb(new Error('Invalid credentials.'))
    var id = users[creds.identity]._id
      , key = genKey()
    sessions[id] = key
    cb(null, { _id: users[creds.identity]._id, key: key })
  }

  return { lookupKey: lookupKey, authenticate: authenticate }

}