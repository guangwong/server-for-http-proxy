'use strict';

/*!
 * OpenSSL-wrapper.js
 * Copyright(c) 2013 Olivier Louvignes <olivier@mg-crea.com>
 * MIT Licensed
 */

/**
 * Module dependencies.
 */
var spawn = require('child_process').spawn;
var debug = require('debug')('openssl-wrapper');

var expected = {
  'smime.verify': '^verification successful',
  'cms.verify': '^verification successful',
  'req.verify': '^verify ok',
  'x509.req': '^signature ok',
  'genrsa': '^generating'
};

/**
 * Execute an OpenSSL command
 *
 * @param {String} action
 * @param {Buffer} buffer
 * @param {Object} options
 * @param {Function} callback
 * @api public
 */
exports.exec = function exec(action, buffer, options, callback) {

  if(!Buffer.isBuffer(buffer)) {
    callback = options;
    options = buffer;
    buffer = false;
  }

  if(typeof options === 'function') {
    callback = options;
    options = {};
  }

  var params = action.split('.').map(function(v, k) {
    return !k ? v : '-' + v;
  });
  var key;
  for (key in options) {
    if(options[key] === false) continue;
    params.push('-' + key);
    if(typeof options[key] === 'string' || typeof options[key] === 'number') {
      params.push(options[key]);
    }
  }
  for (key in options) {
    if(options[key] !== false) continue;
    params.push(key);
  }

  debug('> openssl ' + params.join(' '));
  var openssl = spawn('openssl', params),
    out, outResult = [], errResult = [],
    err, outLength = 0, errLength = 0;

  openssl.stdout.on('data', function (data) {
    outLength += data.length;
    outResult.push(data);
  });

  openssl.stderr.on('data', function (data) {
    errLength += data.length;
    errResult.push(data);
  });

  openssl.on('close', function(code) {
    out = Buffer.concat(outResult, outLength);
    err = Buffer.concat(errResult, errLength).toString('utf8');

    if(!code) {
      err = null;
    }

    if(typeof callback === 'function') {
        callback.apply(null, [err, out]);
    }

  });

  if(buffer) openssl.stdin.write(buffer);
  openssl.stdin.end();

};
