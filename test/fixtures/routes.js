module.exports = createRoutes

function createRoutes(router) {

  router.all('/', function (req, res) {
    res.end('ok')
  })

}