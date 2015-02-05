var ServerForHTTPPRoxy = require("./lib/server-for-http-proxy");

exports.Server = ServerForHTTPPRoxy.Server;
exports.createServer = function(requestListener) {
    return new ServerForHTTPPRoxy.Server(requestListener);
};
