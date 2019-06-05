/* globals Uint8Array */
var Crypto = module.exports;

var Format = require("cryptomancy-format");
var Nacl = require('tweetnacl');

// in theory each key should only be used once
// we could generate a random nonce as a safety net but then we'd have to serialize it
var make_nonce = function () {
    return new Uint8Array(new Array(Nacl.secretbox.nonceLength).fill(0));
};

// encrypt with xsalsa20-poly1305
Crypto.encrypt = function encrypt (key, plain) {
    var u8_plain = Format.decodeUTF8(plain);
    var u8_key = key;
    var u8_nonce = make_nonce();
    var u8_cipher = Nacl.secretbox(u8_plain, u8_nonce, u8_key);
    return Format.encode64(u8_cipher);
};

// decrypt with xsalsa20-poly1305
Crypto.decrypt = function decrypt (key, message) {
    var u8_key = key;
    var u8_cipher = Format.decode64(message);
    var u8_nonce = make_nonce();
    var open = Nacl.secretbox.open(u8_cipher, u8_nonce, u8_key);
    return open? Format.encodeUTF8(open): null;
};

