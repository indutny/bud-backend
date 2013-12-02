#!/usr/bin/env node
var bud = require('..');
var fs = require('fs');
var argv = require('optimist')
    .usage('Usage: $0 --conf config.json')
    .demand(['config'])
    .argv;

try {
  var conf = fs.readFileSync(argv.config);
  conf = JSON.parse(conf.toString());
} catch (e) {
  console.error('Failed to load: ' + argv.conf);
  console.error(e.stack);
  process.exit(1);
}

// Load SNI certificates
if (conf.sni) {
  Object.keys(conf.sni.store).forEach(function(name) {
    var sni = conf.sni.store[name];

    var cert = fs.readFileSync(sni.cert);
    var key = fs.readFileSync(sni.key);

    conf.sni.store[name].cert = cert.toString();
    conf.sni.store[name].key = key.toString();
  });
}

bud.createServer(conf).listen(conf.port, conf.host, function() {
  var addr = this.address();
  console.log('bud.js listening on %s:%d', addr.host, addr.port);
});
