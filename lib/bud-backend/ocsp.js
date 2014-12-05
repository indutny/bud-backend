var express = require('express');
var http = require('http');
var url = require('url');
var rfc2560 = require('asn1.js-rfc2560');
var Buffer = require('buffer').Buffer;

module.exports = function ocsp(options) {
  var cache = new OCSPCache(options);
  var router = new express.Router();

  router.get(options.ocsp.url, function(req, res) {
    cache.probe(req.params.id, function(err, response) {
      if (err)
        return res.json(500, { error: true, reason: err.stack });

      if (response)
        res.json({ response: response });
      else
        res.json(404, { error: true, reason: 'OCSP response not found' });
    });
  });

  router.post(options.ocsp.url, function(req, res) {
    cache.request(req.params.id, req.body, function(err, response) {
      if (err)
        return res.json(500, { error: true, reason: err.stack });

      if (response)
        res.json({ response: response });
      else
        res.json(404, { error: true, reason: 'Response not found' });
    });
  });

  return router.middleware;
}

function OCSPCache(options) {
  this.options = options.ocsp;
  this.cache = {};

  // Override methods
  if (this.options.probe)
    this.probe = this.options.probe;
  if (this.options.store)
    this.probe = this.options.store;
  if (this.options.filter)
    this.filter = this.options.filter;
};

OCSPCache.prototype.filter = function filter(url, callback) {
  callback(null);
};

OCSPCache.prototype.probe = function probe(id, callback) {
  if (this.cache.hasOwnProperty(id))
    callback(null, this.cache[id]);
  else
    callback(null, false);
};

OCSPCache.prototype.store = function store(id, response, maxTime, callback) {
  if (this.cache.hasOwnProperty(id))
    clearTimeout(this.cache[id].timer);
  this.cache[id] = {
    response: response,
    timer: setTimeout(function() {
      delete this.cache[id];
    }, maxTime)
  };

  callback(null, null);
};

OCSPCache.prototype.request = function request(id, data, callback) {
  var self = this;

  function done(err, response) {
    if (callback)
      callback(err, response);
    callback = null;
  }

  // Check that url isn't blacklisted
  this.filter(data.url, function(err) {
    if (err)
      return done(err, null);

    var uri = url.parse(data.url);
    var ocspReq = new Buffer(data.ocsp, 'base64');

    http.request({
      method: 'POST',
      host: uri.host,
      path: uri.path,
      headers: {
        'Content-Type': 'application/ocsp-request',
        'Content-Length': ocspReq.length
      }
    }, onResponse).on('error', done).end(ocspReq);
  });

  function onResponse(response) {
    if (response.statusCode < 200 || response.statusCode >= 400)
      return done(new Error('Failed to obtain OCSP response'));

    var chunks = [];
    response.on('readable', function() {
      chunks.push(response.read());
    });
    response.on('end', function() {
      var ocsp = Buffer.concat(chunks);
      var ocspBase64 = ocsp.toString('base64');

      // Respond early
      done(null, ocspBase64);

      // Try parsing and caching response
      self.getMaxStoreTime(ocsp, function(err, maxTime) {
        if (err)
          return;

        self.store(id, ocspBase64, maxTime, function(err) {
          // No-op
        });
      });
    });
  }
};

OCSPCache.prototype.getMaxStoreTime = function getMaxStoreTime(ocsp, callback) {
  try {
    var response = rfc2560.OCSPResponse.decode(ocsp, 'der');

    var status = response.Status;
    if (status !== 'successful')
      return callback(new Error('Bad OCSP response status: ' + status));

    // Unknown response type
    var responseType =response.responseBytes.responseType;
    if (responseType !== 'id-pkix-ocsp-basic')
      return callback(new Error('Unknown OCSP response type: ' + responseType));

    var bytes = ocsp.responseBytes.response;
    var basic = rfc2560.BasicOCSPResponse.decode(bytes, 'der');
  } catch (e) {
    return callback(e);
  }

  // Not enough responses
  if (basic.tbsResponseData.responses.length === 0)
    return callback(new Error('No OCSP responses'));

  var responses = basic.tbsResponseData.responses;

  // Every response should be positive
  var good = responses.every(function(response) {
    return response.certStatus.type === 'good';
  });

  // No good - no cache
  if (!good)
    return callback(new Error('Some OCSP responses are not good'));

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

  return callback(null, Math.max(0, nextUpdate - new Date));
};
