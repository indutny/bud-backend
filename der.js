var assert = require('assert');
var Buffer = require('buffer').Buffer;

var tagClasses = {
  0: 'universal',
  1: 'application',
  2: 'context',
  3: 'private'
};

var tags = {
  0x00: 'end',
  0x01: 'bool',
  0x02: 'int',
  0x03: 'bitstr',
  0x04: 'octstr',
  0x05: 'null',
  0x06: 'obj',
  0x07: 'objDesc',
  0x08: 'external',
  0x09: 'real',
  0x0a: 'enum',
  0x0b: 'embed',
  0x0c: 'utf8str',
  0x0d: 'relativeOid',
  0x10: 'seq',
  0x11: 'set',
  0x12: 'numstr',
  0x13: 'printstr',
  0x14: 't61str',
  0x15: 'videostr',
  0x16: 'ia5str',
  0x17: 'utctime',
  0x18: 'gentime',
  0x19: 'graphstr',
  0x1a: 'iso646str',
  0x1b: 'genstr',
  0x1c: 'unistr',
  0x1d: 'charstr',
  0x1e: 'bmpstr'
};

function DecoderBuffer(base) {
  assert(Buffer.isBuffer(base));

  this.base = base;
  this.offset = 0;
  this.length = base.length;
};

DecoderBuffer.prototype.readUInt8 = function readUInt8() {
  assert(this.offset + 1 <= this.length);
  return this.base.readUInt8(this.offset++, true);
};

DecoderBuffer.prototype.skip = function skip(bytes) {
  assert(this.offset + bytes <= this.length);
  var res = new DecoderBuffer(this.base);
  res.offset = this.offset;
  res.length = this.offset + bytes;
  this.offset += bytes;
  return res;
};

DecoderBuffer.prototype.raw = function raw() {
  return this.base.slice(this.offset, this.length);
};

function decodeTag(buf) {
  var tag = buf.readUInt8();

  var cls = tagClasses[tag >> 6];
  var primitive = (tag & 0x20) === 0;

  // Multi-octet tag - load
  if ((tag & 0x1f) === 0x1f) {
    var oct = tag;
    tag = 0;
    while ((oct & 0x80) === 0x80) {
      oct = buf.readUInt8();
      tag <<= 7;
      tag |= oct & 0x7f;
    }
  } else {
    tag &= 0x1f;
  }
  var type = tags[tag];

  return {
    cls: cls,
    primitive: primitive,
    tag: tag,
    type: type
  };
}

function decodeLen(buf, primitive) {
  var len = buf.readUInt8();

  // Indefinite form
  if (!primitive && len === 0x80)
    return null;

  // Definite form
  if ((len & 0x80) === 0) {
    // Short form
    return len;
  }

  // Long form
  var num = len & 0x7f;
  assert(num < 4, 'length octect is too long');
  len = 0;
  for (var i = 0; i < num; i++) {
    len <<= 8;
    len |= buf.readUInt8();
  }

  return len;
}

function decodeValue(item) {
  if (item.primitive) {
    if (item.type === 'bool' && item.content.length === 1) {
      return item.content[0] !== 0;
    } else if (item.type === 'int' || item.type === 'enum') {
      var res = 0;
      for (var i = 0; i < item.content.length; i++) {
        res <<= 8;
        res |= item.content[i];
      }
      return res;
    } else if (item.type === 'null' && item.content.length === 0) {
      return null;
    } else if (item.type === 'obj') {
      var identifiers = [];
      var ident = 0;
      for (var i = 0; i < item.content.length; i++) {
        var subident = item.content[i];
        ident <<= 7;
        ident |= subident & 0x7f;
        if ((subident & 0x80) === 0) {
          identifiers.push(ident);
          ident = 0;
        }
      }
      if (subident & 0x80)
        identifiers.push(ident);

      var first = (identifiers[0] / 40) | 0;
      var second = identifiers[0] % 40;
      return {
        relative: identifiers,
        normal: [first, second].concat(identifiers.slice(1))
      };
    } else if (item.type === 'gentime') {
      var str = item.content.toString();
      var year = str.slice(0, 4) | 0;
      var mon = str.slice(4, 6) | 0;
      var day = str.slice(6, 8) | 0;
      var hour = str.slice(8, 10) | 0;
      var min = str.slice(10, 12) | 0;
      var sec = str.slice(12, 14) | 0;

      return new Date(Date.UTC(year, mon - 1, day, hour, min, sec, 0));
    }
  }

  if (item.type === 'bitstr' || item.type === 'octstr') {
    var buf;
    if (item.primitive) {
      buf = item.content;
    } else {
      var isValid = item.content.every(function(subitem) {
        return Buffer.isBuffer(subitem.value);
      });
      if (isValid) {
        buf = Buffer.concat(item.content.map(function(subitem) {
          return subitem.value;
        }));
      }
    }
    if (buf)
      return buf;
  }
}

function decode(buf) {
  var tag = decodeTag(buf);
  var len = decodeLen(buf, tag.primitive);
  var contentBuf = null;
  var content = null;

  if (tag.primitive || len !== null)
    contentBuf = buf.skip(len);
  else
    contentBuf = buf;

  if (!tag.primitive) {
    content = [];

    do {
      // Definite length end
      if (len !== null && contentBuf.offset === contentBuf.length)
        break;

      var item = decode(contentBuf);
      if (!(item.tag === 'end' && item.primitive))
        content.push(item);
    } while (item.tag !== 'end');
  } else {
    content = contentBuf.raw();
  }

  var res = {
    tag: tag.tag,
    type: tag.type,
    cls: tag.cls,
    primitive: tag.primitive,
    content: content,
    value: undefined
  };

  res.value = decodeValue(res);
  return res;
}

exports.decode = function(data) {
  var buf = new DecoderBuffer(data);

  return decode(buf);
};


// Specific DER things

var statusToStr = {
  0: 'successful',
  1: 'malformed_request',
  2: 'internal_error',
  3: 'try_later',
  5: 'sig_required',
  6: 'unauthorized'
};

function decodeBasicOCSP(data) {
  var basic = exports.decode(data);

  assert.equal(basic.type, 'seq');
  assert(basic.content.length >= 3);

  var respData = basic.content[0];
  assert.equal(respData.type, 'seq');
  assert(respData.content.length >= 3);

  // Version
  var version;
  var respDataContent;
  if (respData.content[0].tag === 0) {
    version = respData.content[0].value;
    respDataContent = respData.content.slice(1);
  } else {
    version = 'v1';
    respDataContent = respData.content;
  }
  assert(respDataContent.length >= 3);

  // ResponderID
  var responderId = respDataContent[0];
  if (responderId.tag === 1) {
    responderId = { type: 'byName', value: responderId.value };
  } else if (responderId.tag === 2) {
    responderId = { type: 'byKey', value: responderId.value };
  } else {
    throw new Error('Unexpected responderID');
  }

  assert.equal(respDataContent[1].type, 'gentime');
  var producedAt = respDataContent[1].value;

  var responses = respDataContent[2];
  assert.equal(responses.type, 'seq');
  responses = responses.content.map(function(res) {
    assert.equal(res.type, 'seq');
    assert(res.content.length >= 3);
    assert.equal(res.content[2].type, 'gentime');
    if (res.content.length >= 4) {
      assert.equal(res.content[3].tag, 0);
      assert.equal(res.content[3].content.length, 1);
      assert.equal(res.content[3].content[0].type, 'gentime');
    }

    return {
      thisUpdate: res.content[2].value,
      nextUpdate: res.content[3].content[0].value || null
    };
  });

  return {
    version: version,
    responderId: responderId,
    producedAt: producedAt,
    responses: responses
  };
}

exports.decodeOCSP = function decodeOCSP(data) {
  var resp = exports.decode(data);
  assert.equal(resp.type, 'seq');
  assert.equal(resp.content.length, 2);
  assert.equal(resp.content[0].type, 'enum');

  var status = statusToStr[resp.content[0].value];

  assert.equal(resp.content[1].tag, 0);
  var responseBytes = resp.content[1].content[0];
  assert.equal(responseBytes.type, 'seq');
  assert.equal(responseBytes.content.length, 2);
  assert.equal(responseBytes.content[0].type, 'obj');
  assert.equal(responseBytes.content[1].type, 'octstr');
  var resType = responseBytes.content[0].value.normal.join(' ');
  if (resType === '1 3 6 1 5 5 7 48 1 1')
    data = decodeBasicOCSP(responseBytes.content[1].value);
  else
    data = null;

  return {
    status: status,
    type: resType,
    data: data
  };
}
