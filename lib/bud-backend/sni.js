module.exports = function sni(app, options) {
  var sni = new SNI(options);
  app.get(options.sni.url, function(req, res) {
    sni.lookup(req.params.servername, function(err, ctx) {
      if (err)
        return res.json(500, { error: true, reason: err.stack });

      if (!ctx)
        return res.json(404, { error: true, reason: 'SNI ctx not found' });

      res.json({
        cert: Array.isArray(ctx.cert) ? ctx.cert.map(stringify) :
                                        ctx.cert.toString(),
        key: Array.isArray(ctx.key) ? ctx.key.map(stringify) :
                                      ctx.key.toString(),
        passphrase: Array.isArray(ctx.passphrase) ?
            ctx.passphrase.map(stringify) :
            ctx.passphrase && ctx.passphrase.toString(),
        backend: ctx.backend || null,
        ciphers: ctx.ciphers || null,
        npn: ctx.npn || null,
        ticket_key: ctx.ticket_key || null,
        server_preference: ctx.server_preference || null
      });
    });
  });
};

function stringify(val) {
  return val.toString();
}

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
