var JIFFClient = require('../lib/jiff-client.js');
var jiff_bignumber = require('../lib/ext/jiff-client-bignumber.js');
var jiff_fixedpoint = require('../lib/ext/jiff-client-fixedpoint.js');
var mpc_innerprod = require('./mpc.js');
var input = [ 5.91, 3.73, 50.03]

function onConnect() {
  console.log('All parties connected!');
  mpc_innerprod(jiff_instance, input).then(function (result) {
    console.log('Inner product', result.div(10000));
    console.log('Verify', 1.32*5.91 + 10.22*3.73 + 5.67*50.03);
  });
}

var options = {
  party_count: 2,
  party_id: 2,
  crypto_provider: true,
  Zp: 214749167653,
  onConnect: onConnect,
  autoConnect: false,
  integer_digits: 3,
  decimal_digits: 4
};
var jiff_instance = new JIFFClient('http://server:8080', 'inner-product', options);
jiff_instance.apply_extension(jiff_bignumber, options);
jiff_instance.apply_extension(jiff_fixedpoint, options);
jiff_instance.connect();