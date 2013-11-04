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

  it('should respond with 401 if bad credentials are supplied (POST)', function (done) {

    var r = request(app)
      .post('/')
      .set('Accept', 'application/json')
      .send({ identity: 'paul.serby@clock.co.uk', password: 'password' })
      .end(function (error, res) {
        res.statusCode.should.equal(401)
        r.app.close()
        done()
      })

  })

  it('should respond with 401 if bad credentials are supplied (GET)', function (done) {
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

  it('should respond with 401 if not authenticated and bad credentials are supplied', function (done) {
    var r = request(app)
      .get('/')
      .set('Accept', 'application/json')
      .set('authorization', 'BAD')
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

})