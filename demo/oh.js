var ServerForHTTPProxy = require("../");
ServerForHTTPProxy.createServer(function(req, res){
    res.end(req.isHTTPS);
}).listen(8000);
