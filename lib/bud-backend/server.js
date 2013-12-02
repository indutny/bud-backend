var bud = require('../bud-backend');

var express = require('express');

var server = exports;

server.createServer = function createServer(options) {
  // Set defaults
  if (!options)
    options = {};
  if (!options.sni)
    options.sni = {};
  if (!options.ocsp)
    options.ocsp = {};
  if (!options.sni.url)
    options.sni.url = '/bud/sni/:servername';
  if (!options.ocsp.url)
    options.ocsp.url = '/bud/stapling/:id';
  if (typeof options.sni.enabled !== 'boolean')
    options.sni.enabled = true;
  if (typeof options.ocsp.enabled !== 'boolean')
    options.ocsp.enabled = true;

  // Create server
  var app = express();

  // Parse bodies
  app.use(express.bodyParser());

  if (options.sni.enabled)
    bud.sni(app, options);
  if (options.ocsp.enabled)
    bud.ocsp(app, options);

  return app;
};
