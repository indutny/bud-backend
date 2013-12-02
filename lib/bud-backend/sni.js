module.exports = function sni(app, options) {
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
