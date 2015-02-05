/***
 * 根据域名生成证书，包括缓存证书文件、缓存对象的能力。
 */

var LRU = require("lru-cache");
var Path = require("path");
var Crypto = require("crypto");
var ASync = require("async");
var Promise = require("bluebird");
var FS = Promise.promisifyAll(require('fs'));
var OpenSSL = Promise.promisifyAll(require("./openssl-wrapper"));

var CERTIFICATES_DIR = Path.join(__dirname, "../certificates/");
var CERTIFICATES_CACHE_DIR = Path.join(CERTIFICATES_DIR, "cache");
var CA_CRT_PATH = Path.join(CERTIFICATES_DIR, "ca.crt");
var CA_KEY_PATH = Path.join(CERTIFICATES_DIR, "ca.key");
var OPENSSL_CNF_PATH = Path.join(CERTIFICATES_DIR, "openssl.cnf");

var cache = new LRU({
    max : 500,
    maxAge : 1000 * 60 * 60
});

/**
 * 根据域名获取
 */
exports.take = take;
function take(domain){
    return new Promise(function(resolve){
        if(cache.has(domain)){
            resolve(cache.get(domain))
        }else{
            resolve( createCredentials(domain).then(function(obj){
                cache.set(domain, obj);
                return obj;
            }) );
        }
    });
}

/**
 * 产生 Credentials 对象
 */
function createCredentials(domain){
    var crtPath = Path.join(CERTIFICATES_CACHE_DIR, domain + ".cret");
    var keyPath = Path.join(CERTIFICATES_CACHE_DIR, domain + ".key");

    return new Promise(function(resolve, reject){
        Promise.all([FS.statAsync(crtPath), FS.statAsync(keyPath)])
            .then(function(){
                resolve( createCredentials0(crtPath, keyPath) );
            })
            .error(function(err){
                resolve( genCertificate(domain, crtPath, keyPath).then(function(){
                    return createCredentials0(crtPath, keyPath);
                }) );
            })
    });

}
function createCredentials0(crtPath, keyPath){
    return Promise.join(
        FS.readFileAsync(keyPath + ".nopass"),
        FS.readFileAsync(crtPath),
        function(key, crt){
            return Crypto.createCredentials({
                key: key,
                cert: crt
            });
        }
    );
}

/**
 * 根据域名生成证书并保存于FS中
 */
function genCertificate(domain, crtPath, keyPath){

    var csrPath = keyPath + ".csr";

    return Promise.promisify( ASync.series.bind(
        ASync,
        [
            OpenSSL.exec.bind(OpenSSL, "genrsa", {
                "des3" : true,
                "passout" : "pass:1234",
                "out"  : keyPath,
                "1024" : false
            }),
            OpenSSL.exec.bind(OpenSSL, "req", {
                "new" : true,
                "config" : OPENSSL_CNF_PATH,
                "passin" : "pass:1234",
                "subj" : "/CN=" + domain,
                "key" : keyPath,
                "out" : csrPath
            }),
            OpenSSL.exec.bind(OpenSSL, "x509", {
                "req" : true,
                "passin" : "pass:1234",
                "days" : "730",
                "in" : csrPath,
                "CA" : CA_CRT_PATH,
                "CAkey" : CA_KEY_PATH,
                "set_serial" : "01",
                "out" : crtPath
            }),
            OpenSSL.exec.bind(OpenSSL, "rsa", {
                "passin" : "pass:1234",
                "in" : keyPath,
                "out" : keyPath + ".nopass"
            })
        ]
    ) )();


}































