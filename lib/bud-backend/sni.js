module.exports = function sni(app, options) {
  var sni = new SNI(options);
  app.get(options.sni.url, function(req, res) {
    sni.lookup(req.params.servername, function(err, ctx) {
      if (err)
        return res.json(500, { error: true, reason: err.stack });

      if (!ctx)
        return res.json(404, { error: true, reason: 'SNI ctx not found' });

      res.json({
        cert: ctx.cert.toString(),
        key: ctx.key.toString(),
        backend: ctx.backend || null,
        ciphers: ctx.ciphers || null,
        npn: ctx.npn || null,
        proxyline: ctx.proxyline || null,
        'x-forward': ctx['x-forward'] || null
      });
    });
  });
};

function SNI(options) {
  this.options = options.sni;

  this.store = this.options.store;
  if (this.options.lookup)
    this.lookup = this.options.lookup;
}

SNI.prototype.lookup = function(servername, callback) {
  if (this.store.hasOwnProperty(servername))
    callback(null, this.store[servername]);
  else
    callback(null, false);
};
