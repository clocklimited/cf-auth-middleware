var getCredentials = require('../get-credentials')
var assert = require('assert')

describe('#getCredentials()', function () {
  it('should return error if neither authentication header or querystring is not provided', function () {
    assert.throws(function () {
      getCredentials({ headers: {}, query: {} })
    }, /Missing authorization token/)
  })

  describe('header based authentication', function () {
    it('should return error if header authentication is not Catfish', function () {
      assert.throws(function () {
        getCredentials({ headers: { authorization: 'not catfish auth' } })
      }, /Invalid authorization type/)
    })

    it('should return error if header authentication is not in the correct format', function () {
      assert.throws(function () {
        getCredentials({ headers: { authorization: 'Catfish asdsdsaasddsa' } })
      }, /Invalid authorization format/)
    })

    it('should return an object with properties `id` and `signature`', function () {
      var parsed = getCredentials({ headers: { authorization: 'Catfish 123:abc' } })
      assert.equal(parsed.id, '123')
      assert.equal(parsed.signature, 'abc')
    })
  })

  describe('querystring based authentication', function () {
    it('should return error if querystring authentication is not in the correct format', function () {
      assert.throws(function () {
        getCredentials({ headers: {}, query: { authorization: 'not catfish auth' } })
      }, /Invalid authorization format/)
    })

    it('should return an object with properties `id` and `signature`', function () {
      var parsed = getCredentials({ headers: {}, query: { authorization: '123:abc' } })
      assert.equal(parsed.id, '123')
      assert.equal(parsed.signature, 'abc')
    })
  })
})
