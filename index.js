var ServerForHTTPPRoxy = require("./lib/http-server-supported-https");

exports.Server = ServerForHTTPPRoxy.Server;
exports.createServer = function(requestListener) {
    return new ServerForHTTPPRoxy.Server(requestListener);
};
