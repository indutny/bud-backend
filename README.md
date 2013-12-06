# bud-backend

An example/template backend for [bud][0].

## Usage

### CLI

```bash
$ npm install -g bud-backend
$ cat > config.json <<JSON
{
  "port": 9000,
  "host": "127.0.0.1",
  "sni": {
    "enabled": true,
    "store": {
      "example.com": {
        "cert": "keys/cert.pem",
        "key": "keys/key.pem"
      }
    }
  }
}
JSON
$ bud-backend --conf config.json
```

### Module

```javascript
var bud = require('bud-backend');

bud.createServer({
  // Server Name Indication configuration
  sni: {
    enabled: true,

    store: {},

    // *Optional* lookup function, if present - `store` may be omitted
    lookup: function (servername, callback) {
      callback(null, {
        cert: '-----BEGIN CERTIFICATE-----\n...',
        key: '-----BEGIN RSA PRIVATE KEY-----\n...',

        // Optional
        npn: [ ... ],
        ciphers: 'RSA-OMG-SECURE-128:RSA-OMG'
      });
    }
  },

  // OCSP Stapling cache configuration
  ocsp: {
    enabled: true,

    // Optional, filter OCSP urls
    filter: function (url, callback) {
      if (/* url is known and whitelisted */)
        callback(null);
      else
        callback(new Error('Url is not whitelisted'));
    },

    // Optional
    store: function (key, value, maxTime, callback) {
      // Should store `value` under the `key` with maximum TTL `maxTime`
      // (in milliseconds) in backend storage and invoke callback, once
      // ready.
    },

    // Optional, must be present if `store` is used
    probe: function (key, callback) {
      callback(null, data);
    }
  }
})
```

#### LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2013.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[0]: https://github.com/indutny/bud
