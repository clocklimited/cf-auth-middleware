var request = require('supertest')
  , createMiddleware = require('../')
  , authProvider = require('./fixtures/auth-provider')()
  , createRoutes = require('./fixtures/routes')
  , createSignature = require('./fixtures/signature')
  , express = require('express')
  , noopLogger = { debug: noop, info: noop, warn: noop, error: noop }

function noop() {}

var app = express()
app.use(createMiddleware(authProvider, { logger: noopLogger }))
createRoutes(app)

var authedAdministrator
before(function(done) {
  authProvider.authenticate(
    { identity: 'ben.gourley@clock.co.uk'
    , password: 'hai'
    }, function (err, res) {
      if (err) return done(err)
      authedAdministrator = res
      done()
    })
})

describe('authentication middleware', function () {

  it('should error if the provided authProvider lacks an authenticate() function', function () {

    (function () {
      createMiddleware({})
    }).should.throw('Expecting an authenticate function')

  })

  it('should error if the provided authProvider lacks a lookupKey() function', function () {

    (function () {
      createMiddleware({ authenticate: function () {} })
    }).should.throw('Expecting a lookupKey function')

  })

  it('should respond with 401 if no credentials are supplied (POST)', function (done) {

    var r = request(app)
      .post('/')
      .set('Accept', 'application/json')
      .end(function (error, res) {
        res.statusCode.should.equal(401)
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
        res.headers['www-authenticate'].should.equal('Catfish')
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
        res.headers['www-authenticate'].should.equal('Catfish')
        r.app.close()
        done()
      })
  })


  it('should respond with a 200 if a good signature is supplied on GET', function (done) {

    var date = (new Date()).toUTCString()
      , hash = createSignature(authedAdministrator.key, 'GET', '', date, '/')

    var r = request(app)
      .get('/')
      .set('Accept', 'application/json')
      .set('x-cf-date', date)
      .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
      .end(function (error, res) {
        res.statusCode.should.equal(200)
        r.app.close()
        done()
      })

  })

  it('should respond with a 200 if a good signature is supplied on POST', function (done) {

    var date = (new Date()).toUTCString()
      , hash = createSignature(authedAdministrator.key, 'POST', 'application/json', date, '/')

    var r = request(app)
      .post('/')
      .send({ some: 'Date', onThe: 'POST request' })
      .set('Accept', 'application/json')
      .set('x-cf-date', date)
      .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
      .end(function (error, res) {
        res.statusCode.should.equal(200)
        r.app.close()
        done()
      })

  })

  // This is skipped until https://github.com/visionmedia/superagent/pull/284 is merged and supertest is updated
  // because .set('Content-Type', x) can't hande the charset part.
  it.skip('should work when the charset parameter of the Content-Type header is set', function (done) {
    var date = (new Date()).toUTCString()
      , hash = createSignature(authedAdministrator.key, 'POST', 'application/json', date, '/')

    var r = request(app)
      .post('/')
      .send({ some: 'Date', onThe: 'POST request' })
      .set('Accept', 'application/json')
      .set('x-cf-date', date)
      .set('Authorization', 'Catfish ' + authedAdministrator._id + ':' + hash)
      .set('Content-Type', 'application/json; charset=utf-8')
      .end(function (error, res) {
        res.statusCode.should.equal(200)
        r.app.close()
        done()
      })

  })

  it('should not try to authenticate OPTIONS requests', function (done) {
    var r = request(app)
      .options('/')
      .end(function (error, res) {
        res.statusCode.should.equal(200)
        r.app.close()
        done()
      })
  })

  it('should fail to authenticate if the authProvider errors while looking up the key', function (done) {
    var r = request(app)
      .get('/')
      .set('Authorization', 'Catfish fail:xyz')
      .end(function (error, res) {
        res.statusCode.should.equal(401)
        r.app.close()
        done()
      })
  })

})