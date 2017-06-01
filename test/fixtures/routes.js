function createRoutes (router) {
  router.all('/', function (req, res) {
    res.end('ok')
  })
}

module.exports = createRoutes
