// HTTPS 代理的简单示例
var HTTP = require("http");
var inherits = require('util').inherits;
var TLS = require("tls");
var CertificateStore = require("./certificate-store.js")



exports.createServer = function(requestListener) {
    return new Server(requestListener);
};

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


