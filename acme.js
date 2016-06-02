//https://github.com/ietf-wg-acme/acme
var cluster = require('cluster');
var http = require('http');
var url = require("url");
var acme = require('./acme-forge.js');
var fs = require('fs');
var chain=[];


if (cluster.isMaster) {

  // Start workers and listen for messages containing notifyRequest
  const numCPUs = require('os').cpus().length;
  for (var i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

} else {

  // Worker processes have a http server.
  http.Server((req, res) => {
    var pathname = url.parse(req.url).pathname;
    if (pathname=='/favicon.ico'){
      res.writeHead(404, {"Content-Type": "text/plain"});
      res.end("Not Found");
    }else if (pathname=='/setup-ca'){
      acme.createChain(chain);
      
      console.log("Request for " + pathname + " received.");
      res.writeHead(200);
      var readStream = fs.createReadStream(chain[chain.length-1].pemChanFile);
      // We replaced all the event handlers with a simple call to readStream.pipe()
      readStream.pipe(res);
    }else if (pathname=='/new-cert'){
      var newCert=acme.newCert(chain);
      console.log("Request for " + pathname + " received.");
      res.writeHead(200);
      res.end(newCert.certificate);
    }else{
      console.log("Request for " + pathname + " received.");
      res.writeHead(200);
      res.end('hello world\n');

      // notify master about the request
      process.send({ cmd: 'notifyRequest' });
    }
  }).listen(8000);
}
