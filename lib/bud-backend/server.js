var bud = require('../bud-backend');

var express = require('express');
var util = require('util');

var server = exports;

server.createServer = function createServer(options) {
  options = util._extend({
    staplingUrl: '/bud/stapling/:id',
    sniUrl: '/bud/sni/:id',
    sni: {}
  }, options || {});

  var app = express();

  app.use(express.bodyParser());

  bud.sni(app, options);
  bud.ocsp(app, options);

  return app;
};
