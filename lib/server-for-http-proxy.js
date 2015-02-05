// HTTPS 代理的简单示例
var HTTP = require("http");
var inherits = require('util').inherits;
var tls = TLS = require("tls");
var TLSConnect = require("tls-connect");
var CertificateStore = require("./certificate-store")

exports.Server = Server;
inherits(Server, HTTP.Server);
function Server(requestListener){
    var self = this;
    HTTP.Server.call(this);
    self.on("request", function(req){
        req.isHTTPS = (req.socket instanceof TLS.TLSSocket);
        if(req.isHTTPS){
            // 整成 HTTP 代理的形式
            req.url = "https://" + req.headers.host + req.url;
        }

    });
    self.on("request", requestListener);
    self.on("secureConnection", function(tlsSocket){
        HTTP._connectionListener.call(self, tlsSocket);
    });
    self.on("connect", function (req, socket, head) {
        var hostName = req.headers.host.split(":")[0];

        socket.write("HTTP/1.1 200 Connection established\r\n\r\n");
        CertificateStore.take(hostName)
            .then(function(credentials){

                var tlsSocket = legacyConnect(hostName, {
                    socket : socket,
                    credentials: credentials,
                    isServer: true,
                    server: self,
                    SNICallback: function (servername, callback) {
                        callback(null, credentials.context);
                    }
                }, credentials);


                socket.on('secure', function() {
                    var ssl = socket._ssl || socket.ssl;
                    var verifyError = ssl.verifyError();

                    // Verify that server's identity matches it's certificate's names
                    if (!verifyError) {
                        var cert = result.getPeerCertificate();
                        var validCert = __checkServerIdentity(hostname, cert);
                        if (!validCert) {
                            verifyError = new Error('Hostname/IP doesn\'t match certificate\'s ' +
                                'altnames');
                        }
                    }

                    if (verifyError) {
                        result.authorized = false;
                        result.authorizationError = verifyError.message;

                        if (options.rejectUnauthorized) {
                            result.emit('error', verifyError);
                            result.destroy();
                            return;
                        } else {
                            result.emit('secureConnect');
                        }
                    } else {
                        result.authorized = true;
                        result.emit('secureConnect');
                    }

                    // Uncork incoming data
                    result.removeListener('end', onHangUp);
                });


                return;
                TLSConnect.connect({
                    socket : socket,
                    credentials: credentials,
                    isServer: true,
                    server: self,
                    SNICallback: function (servername, callback) {
                        callback(null, credentials.context);
                    }
                });
                return;

                var tlsSocket = new TLS.TLSSocket(socket, {
                    credentials: credentials,
                    isServer: true,
                    server: self,
                    SNICallback: function (servername, callback) {
                        callback(null, credentials.context);
                    }
                });
                tlsSocket.on("secure", function () {
                    if (tlsSocket._requestCert) {
                        var verifyError = tlsSocket.ssl.verifyError();
                        if (verifyError) {
                            tlsSocket.authorizationError = verifyError.code;

                            if (tlsSocket._rejectUnauthorized)
                                tlsSocket.destroy();
                        } else {
                            tlsSocket.authorized = true;
                        }
                    }

                    if (!tlsSocket.destroyed && tlsSocket._releaseControl()){
                        self.emit('secureConnection', tlsSocket);
                    }
                });
                var errorEmitted = false;
                tlsSocket.on('close', function() {
                    // Emit ECONNRESET
                    if (!tlsSocket._controlReleased && !errorEmitted) {
                        errorEmitted = true;
                        var connReset = new Error('socket hang up');
                        connReset.code = 'ECONNRESET';
                        self.emit('clientError', connReset, tlsSocket);
                    }
                });

                tlsSocket.on('_tlsError', function(err) {
                    if (!tlsSocket._controlReleased && !errorEmitted) {
                        errorEmitted = true;
                        self.emit('clientError', err, tlsSocket);
                    }
                });

            })
            .error(function(){
                socket.end();
            });
    });
}





function legacyPipe(pair, socket) {
    pair.encrypted.pipe(socket);
    socket.pipe(pair.encrypted);

    pair.encrypted.on('close', function() {
        process.nextTick(function() {
            // Encrypted should be unpiped from socket to prevent possible
            // write after destroy.
            if (pair.encrypted.unpipe)
                pair.encrypted.unpipe(socket);
            socket.destroySoon();
        });
    });

    pair.fd = socket.fd;
    pair._handle = socket._handle;
    var cleartext = pair.cleartext;
    cleartext.socket = socket;
    cleartext.encrypted = pair.encrypted;
    cleartext.authorized = false;

    // cycle the data whenever the socket drains, so that
    // we can pull some more into it.  normally this would
    // be handled by the fact that pipe() triggers read() calls
    // on writable.drain, but CryptoStreams are a bit more
    // complicated.  Since the encrypted side actually gets
    // its data from the cleartext side, we have to give it a
    // light kick to get in motion again.
    socket.on('drain', function() {
        if (pair.encrypted._pending && pair.encrypted._writePending)
            pair.encrypted._writePending();
        if (pair.cleartext._pending && pair.cleartext._writePending)
            pair.cleartext._writePending();
        if (pair.encrypted.read)
            pair.encrypted.read(0);
        if (pair.cleartext.read)
            pair.cleartext.read(0);
    });

    function onerror(e) {
        if (cleartext._controlReleased) {
            cleartext.emit('error', e);
        }
    }

    function onclose() {
        socket.removeListener('error', onerror);
        socket.removeListener('timeout', ontimeout);
    }

    function ontimeout() {
        cleartext.emit('timeout');
    }

    socket.on('error', onerror);
    socket.on('close', onclose);
    socket.on('timeout', ontimeout);

    return cleartext;
};
function legacyConnect(hostname, options, credentials) {
    var pair = tls.createSecurePair(credentials,
        !!options.isServer,
        !!options.requestCert,
        !!options.rejectUnauthorized,
        {
            //NPNProtocols: NPN.NPNProtocols,
            servername: hostname
        });

    legacyPipe(pair, options.socket);
    pair.cleartext._controlReleased = true;
    pair.on('error', function(err) {
        pair.cleartext.emit('error', err);
    });

    return pair;
}
