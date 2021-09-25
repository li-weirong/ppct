module.exports = function (jiffClient, input) {
  var promise = jiffClient.share_array(input);
  return promise.then(function (arrays) {
    var array1 = arrays[1];
    var array2 = arrays[2];
    var result = array1[0].smult(array2[0],null,false);
    for (var i = 1; i < array1.length; i++) {
      result = result.sadd(array1[i].smult(array2[i],null,false));
    }
    return jiffClient.open(result);
  });
};