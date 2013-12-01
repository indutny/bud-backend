var express = require('express');
var http = require('http');
var util = require('util');
var url = require('url');
var rfc2560 = require('asn1.js-rfc2560');
var Buffer = require('buffer').Buffer;

var bud = exports;

bud.create = function create(options) {
  options = util._extend({
    staplingUrl: '/bud/stapling/:id',
    sniUrl: '/bud/sni/:id',
    sni: {}
  }, options || {});

  var app = express();

  app.use(express.bodyParser());

  initSNI(app, options);
  initOCSP(app, options);

  return app;
};

function initSNI(app, options) {
  app.get(options.sniUrl, function(req, res) {
    if (!options.sni.hasOwnProperty(req.params.id))
      return res.json(404, { error: true, reason: 'Not found' });

    var ctx = options.sni[req.params.id];
    res.json({
      cert: ctx.cert,
      key: ctx.key,
      ciphers: ctx.ciphers,
      npn: ctx.npn
    });
  });
};


function initOCSP(app, options) {
  var cache = {};

  function cacheAdd(key, value, ocspRaw) {
    try {
      var ocsp = rfc2560.OCSPResponse.decode(ocspRaw, 'der');

      if (ocsp.responseStatus !== 'successful')
        return;

      // Unknown response type
      if (ocsp.responseBytes.responseType !== 'id-pkix-ocsp-basic')
        return;

      var basic = rfc2560.BasicOCSPResponse.decode(ocsp.responseBytes.response,
                                                   'der');
    } catch (e) {
      // Ignore error
      console.log(e.stack);
      return;
    }

    // Not enough responses
    if (basic.tbsResponseData.responses.length === 0)
      return;
    var responses = basic.tbsResponseData.responses;

    var good = responses.every(function(response) {
      return response.certStatus.type === 'good';
    });

    // No good - no cache
    if (!good)
      return;

    // Find minimum nextUpdate time
    var nextUpdate = 0;
    for (var i = 0; i < responses.length; i++) {
      var response = responses[i];
      var responseNext = response.nextUpdate;
      if (!responseNext)
        continue;

      if (nextUpdate === 0 || nextUpdate > responseNext)
        nextUpdate = responseNext;
    }

    // TODO(indutny): use default interval
    if (nextUpdate === 0 || nextUpdate < +new Date)
      return;

    if (cache[key])
      clearTimeout(cache[key].timeout);

    var item = {
      value: value,
      timeout: setTimeout(function() {
        if (item !== cache[key])
          return;
        delete cache[key];
      }, nextUpdate - new Date)
    };
    cache[key] = item;
  }

  app.get(options.staplingUrl, function(req, res) {
    if (cache.hasOwnProperty(req.params.id)) {
      res.json({ response: cache[req.params.id].value });
    } else {
      res.json(404, { error: true, reason: 'OCSP response not found' });
    }
  });

  app.post(options.staplingUrl, function(req, res) {
    var uri = url.parse(req.body.url);
    var ocspReq = new Buffer(req.body.ocsp, 'base64');

    http.request({
      method: 'POST',
      host: uri.host,
      port: 80,
      path: uri.path,
      headers: {
        'Content-Type': 'application/ocsp-request',
        'Content-Length': ocspReq.length
      }
    }, function(response) {
      if (response.statusCode < 200 || response.statusCode >= 400) {
        return res.json(500, {
          error: true,
          reason: 'Failed to obtain OCSP response'
        });
      }

      var chunks = [];
      response.on('readable', function() {
        chunks.push(response.read());
      });
      response.on('end', function() {
        var ocspResRaw = Buffer.concat(chunks);
        var ocspResBase64 = ocspResRaw.toString('base64');
        res.json({ response: ocspResBase64 });

        // Try parsing and caching response
        cacheAdd(req.params.id, ocspResBase64, ocspResRaw);
      });
    }).on('error', function(err) {
      res.json(500, { error: true, reason: err.message });
    }).end(ocspReq);
  });
}
