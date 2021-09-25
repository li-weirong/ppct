var http = require('http');
var JIFFServer = require('../lib/jiff-server.js');
var jiff_bignumber = require('../lib/ext/jiff-server-bignumber.js');
var express = require('express');
var app = express();
http = http.Server(app);
var jiff_instance = new JIFFServer(http);
jiff_instance.apply_extension(jiff_bignumber);
http.listen(8080, function () {
  console.log('listening on *:8080');
});