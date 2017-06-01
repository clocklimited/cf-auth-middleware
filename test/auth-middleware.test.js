var request = require('supertest')
var createMiddleware = require('..')
var authProvider = require('./fixtures/auth-provider')()
var createRoutes = require('./fixtures/routes')
var createSignature = require('cf-signature')
var express = require('express')
var assert = require('assert')

var app = express()
app.use(createMiddleware(authProvider))
createRoutes(app)

var authedAdministrator

describe('authentication middleware', function () {
  before(function (done) {
    authProvider.authenticate({
      identity: 'ben.gourley@clock.co.uk',
      password: 'hai'
    }, function (err, res) {
      if (err) return done(err)
      authedAdministrator = res
      done()
    })
  })

  it('should error if the provided authProvider lacks an authenticate() function', function () {
    assert.throws(function () {
      createMiddleware({})
    }, /Expecting an authenticate function/)
  })

  it('should error if the provided authProvider lacks a lookupKey() function', function () {
    assert.throws(function () {
      createMiddleware({ authenticate: function () {} })
    }, /Expecting a lookupKey function/)
  })

  it('should respond with 401 if no credentials are supplied (POST)', function (done) {
    var r = request(app)
      .post('/')
      .set('Accept', 'application/json')
      .end(function (error, res) {
        if (error) return done(error)
        assert.equal(res.statusCode, 401)
        r.app.close()
        done()
      })
  })

  it('should respond with 401 if no credentials are supplied (GET)', function (done) {
    var r = request(app)
      .get('/')
      .set('Accept', 'application/json')
      .expect(401)
      .end(function (error, res) {
        if (error) return done(error)
        assert.equal(res.headers['www-authenticate'], 'Catfish')
        r.app.close()
        done()
      })
  })

  it('should respond with 401 if bad credentials are supplied', function (done) {
    var r = request(app)
      .get('/')
      .set('Accept', 'application/json')
      .set('authorization', 'Catfish x:y')
      .expect(401)
      .end(function (error, res) {
        if (error) return done(error)
        assert.equal(res.headers['www-authenticate'], 'Catfish')
        r.app.close()
        done()
      })
  })

  it('should respond with a 401 if no x-cf-date is present in header', function (done) {
    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', date, '/')
    var r = request(app)
        .get('/')
        .set('Accept', 'application/json')
        .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 401)
          r.app.close()
          done()
        })
  })

  it('should respond with a 401 if an x-cf-date is outside of the acceptable default ttl (60s)', function (done) {
    var date = new Date()
    date.setHours(date.getHours() + 12)
    var dateString = date.toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', dateString, '/')
    var r = request(app)
        .get('/')
        .set('Accept', 'application/json')
        .set('x-cf-date', dateString)
        .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 401)
          r.app.close()
          done()
        })
  })

  it('should respond with a 401 if an x-cf-date is outside of the acceptable custom ttl', function (done) {
    var date = new Date()
    date.setHours(date.getHours() + 36)
    var dateString = date.toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', dateString, '/')
    var r = request(app)
        .get('/')
        .set('Accept', 'application/json')
        .set('x-cf-date', dateString)
        .set('x-cf-ttl', '86400000')
        .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 401)
          r.app.close()
          done()
        })
  })

  it('should respond with a 200 if a good signature is supplied on GET', function (done) {
    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', date, '/')
    var r = request(app)
        .get('/')
        .set('Accept', 'application/json')
        .set('x-cf-date', date)
        .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 200)
          r.app.close()
          done()
        })
  })

  it('should respond with a 200 if a good signature is supplied on GET with a custom TTL', function (done) {
    var date = new Date()
    date.setHours(date.getHours() + 12)
    var dateString = date.toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', dateString, '/', 86400000)
    var r = request(app)
        .get('/')
        .set('Accept', 'application/json')
        .set('x-cf-date', dateString)
        .set('x-cf-ttl', '86400000')
        .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 200)
          r.app.close()
          done()
        })
  })

  it('should respond with a 200 if a good signature is supplied on POST', function (done) {
    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'POST', 'application/json', date, '/')
    var r = request(app)
        .post('/')
        .send({ some: 'Date', onThe: 'POST request' })
        .set('Accept', 'application/json')
        .set('x-cf-date', date)
        .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 200)
          r.app.close()
          done()
        })
  })

  it('should work when the charset parameter of the Content-Type header is set', function (done) {
    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'POST', 'application/json', date, '/')
    var r = request(app)
        .post('/')
        .send({ some: 'Date', onThe: 'POST request' })
        .set('Accept', 'application/json')
        .set('x-cf-date', date)
        .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
        .set('Content-Type', 'application/json; charset=utf-8')
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 200)
          r.app.close()
          done()
        })
  })

  it('should not try to authenticate OPTIONS requests', function (done) {
    var r = request(app)
      .options('/')
      .end(function (error, res) {
        if (error) return done(error)
        assert.equal(res.statusCode, 200)
        r.app.close()
        done()
      })
  })

  it('should fail to authenticate if the authProvider errors while looking up the key', function (done) {
    var r = request(app)
      .get('/')
      .set('Authorization', 'Catfish fail:xyz')
      .end(function (error, res) {
        if (error) return done(error)
        assert.equal(res.statusCode, 401)
        r.app.close()
        done()
      })
  })

  it('should assign the authed client\'s id to req[reqProperty]', function (done) {
    var app2 = express()
    app2.use(createMiddleware(authProvider))
    app2.use(function (req, res, next) {
      assert.equal(req.authedClient, authedAdministrator._id)
      next()
    })
    createRoutes(app2)

    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', date, '/')
    var r = request(app2)
      .get('/')
      .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
      .end(function () {
        r.app.close()
        done()
      })
  })

  it('should support a custom reqProperty', function (done) {
    var app2 = express()
    app2.use(createMiddleware(authProvider, { reqProperty: 'ohla' }))
    app2.use(function (req, res, next) {
      assert.equal(req.ohla, authedAdministrator._id)
      next()
    })
    createRoutes(app2)

    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', date, '/')
    var r = request(app2)
      .get('/')
      .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
      .end(function () {
        r.app.close()
        done()
      })
  })

  it('should support a querystring in the url', function (done) {
    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', date, '/?foo=bar')
    var r = request(app)
      .get('/?foo=bar')
      .set('Accept', 'application/json')
      .set('x-cf-date', date)
      .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
      .end(function (error, res) {
        if (error) return done(error)
        assert.equal(res.statusCode, 200)
        r.app.close()
        done()
      })
  })

  it('should allow you to ignore certain querystring keys', function (done) {
    var app2 = express()
    app2.use(createMiddleware(authProvider, { ignoreQueryKeys: [ 'ignored' ] }))
    createRoutes(app2)

    var date = (new Date()).toUTCString()
    var hash = createSignature(authedAdministrator.key, 'GET', '', date, '/')

    request(app2)
      .get('/?ignored=1')
      .set('x-cf-date', date)
      .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
      .end(function (error, res) {
        if (error) return done(error)
        assert.equal(res.statusCode, 200)
        done()
      })
  })

  describe('querystring base authentication', function () {
    it('should respond with a 200 if a good signature via querystring is supplied on GET', function (done) {
      var date = (new Date()).getTime()
      var hash = createSignature(authedAdministrator.key, 'GET', '', date, '/')
      var url = '/?authorization=' + authedAdministrator._id + ':' + encodeURIComponent(hash) + '&x-cf-date=' + date
      var r = request(app)
        .get(url)
        .set('Accept', 'application/json')
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 200)
          r.app.close()
          done()
        })
    })

    it('should respond with a 200 if a good signature via querystring is supplied with a custom TTL', function (done) {
      var date = new Date()
      date.setHours(date.getHours() + 12)
      var dateString = date.getTime()
      var hash = createSignature(authedAdministrator.key, 'GET', '', dateString, '/', 86400000)
      var url = '/?authorization=' + authedAdministrator._id + ':' + encodeURIComponent(hash) +
        '&x-cf-date=' + dateString + '&x-cf-ttl=86400000'
      var r = request(app)
        .get(url)
        .set('Accept', 'application/json')
        .end(function (error, res) {
          if (error) return done(error)
          assert.equal(res.statusCode, 200)
          r.app.close()
          done()
        })
    })
  })
})

describe('#validSignature()', function () {
  var validSignature = createMiddleware.validSignature

  it('should be exported as a separate function for use in non-express auth', function () {
    assert.equal(typeof validSignature, 'function')
  })

  it('should allow ignoring of other querystring keys', function () {
    var method = 'GET'
    var date = new Date().getTime()
    var path = '/a/b/c'
    var request = { url: path + '?d=1&e=2', method: method, headers: {} }
    var authPacket = { date: date }
    var key = '123'
    var signature = createSignature(key, method, '', date, path)
    var invalid = validSignature(request, authPacket, key, signature)
    var valid = validSignature(request, authPacket, key, signature,
      { ignoreQueryKeys: [ 'd', 'e' ] })

    // Request is invalid when query string is taken into account
    assert.equal(invalid, false)

    // But valid when query string keys are ignored
    assert.equal(valid, true)
  })
})
