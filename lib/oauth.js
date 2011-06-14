var querystring = require('querystring'),
  crypto = require('crypto');

function getNonce(len) {
  var nonce = [];
  var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
  for (var i = 0; i < (len ? len : 32); i++) {
    var pos = Math.floor(Math.random()*chars.length);
    nonce.push(chars.substr(pos,1));
  }
  return(nonce.join(''));
}

exports.signature = function(url, options){
  // Default some options
  options.oauthSignatureMethod = options.oauthSignatureMethod||"HMAC-SHA1"
  // note that `url` is a parsed object from restler
  var httpMethod = options.method.toUpperCase();

  // 1. NORMALIZE URL
  // Turn protocol into lower case
  var normalizedURL = [
                       url.protocol.toLowerCase(), 
                       '//', url.hostname, 
                       ((url.protocol==='http:' && url.port==='80') || (url.protocol==='https:' && url.port==='443') ? '' : ':' + url.port),
                       url.pathname
                       ].join('');

  // 2. NORMALIZE PARAMS (not sure if this is needed by restler, but good as a general approach)
  var params = querystring.parse(url.query);
  params['oauth_timestamp'] = Math.round((+(new Date)/1000));
  console.log(params['oauth_timestamp']);
  params['oauth_nonce'] = getNonce();
  params['oauth_version'] = '1.0';
  params['oauth_signature_method'] = options.oauthSignatureMethod;
  params['oauth_consumer_key'] = options.oauthConsumerKey;
  params['oauth_token'] = options.oauthAccessToken;
  // order by parameter name
  var keys = [];
  for(var key in params) keys.push(key);
  keys.sort();
  // build a normalized querystring
  var normalizedParts = [];
  keys.forEach(function(key){
      normalizedParts.push([encodeURIComponent(key), '=', encodeURIComponent(params[key])].join(''));
    });
  normalizedParams = normalizedParts.join('&')

  // 3. Create a base string for signatures
  var signatureBaseString = [httpMethod, encodeURIComponent(normalizedURL), encodeURIComponent(normalizedParams)].join('&');
  console.log(signatureBaseString);

  // 4. And actually sign the string
  var signatureSecret = [encodeURIComponent(options.oauthConsumerSecret), encodeURIComponent(options.oauthAccessTokenSecret)].join('&');
  if (options.oauthSignatureMethod==="HMAC-SHA1") {
    var hash = crypto.createHmac("sha1", signatureSecret).update(signatureBaseString).digest("base64");
  } else {
    var hash = encodeURICompanent(signatureSecret);
  }

  // 5. Build the Authentication 
  // select out the relevant heders, and build yet another string
  var normalizedHeaderParts = [];
  keys.forEach(function(key){
      if(key.match(/^oauth_/)) {
        normalizedHeaderParts.push([encodeURIComponent(key), '="', encodeURIComponent(params[key]), '"'].join(''));
      }
    });
  normalizedHeaderParts.push(['oauth_signature="', hash, '"'].join(''));
  normalizedHeader = 'OAuth ' + normalizedHeaderParts.join(', ');
  
  // 6. Finally return our header
  return(normalizedHeader);
}