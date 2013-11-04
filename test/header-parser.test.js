var parseHeader = require('../header-parser')

describe('#parseAuthHeader()', function () {

  it('should return error if authentication header is not provided', function () {
    var parsed = parseHeader({ headers: {} })
    parsed.should.be.an.instanceOf(Error)
    parsed.message.should.equal('Missing authorization header')
  })

  it('should return error if authentication is not Catfish', function () {
    var parsed = parseHeader({ headers: { authorization: 'not catfish auth' }})
    parsed.should.be.an.instanceOf(Error)
    parsed.message.should.equal('Invalid authorization type')
  })

  it('should return error if authentication is not in the correct format', function () {
    var parsed = parseHeader({ headers: { authorization: 'Catfish asdsdsaasddsa' }})
    parsed.should.be.an.instanceOf(Error)
    parsed.message.should.equal('Invalid authorization format')
  })

  it('should return an object with keys `id` and `key`', function () {
    var parsed = parseHeader({ headers: { authorization: 'Catfish 123:abc' }})
    parsed.should.have.keys(['id', 'key'])
    parsed.id.should.equal('123')
    parsed.key.should.equal('abc')
  })

})