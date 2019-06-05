var BigInteger = require('jsbn').BigInteger;

var Nacl = require('tweetnacl');
var Format = require("cryptomancy-format");
var Source = require("cryptomancy-source");
var Prime = require("cryptomancy-prime");

var OT = module.exports;

OT.genkeys = function genkeys () {
    return {
        E: new BigInteger('65537'),
        N: Prime.sync(Source.bytes.secure(), 1024), // TODO figure out if 4096 is an ok value to use
    };
};

// Alice uses her secret to create a value to give to Bob
OT.mask = function mask (parameters, alice_secret) {
    alice_secret = Format.encodeBigInt(alice_secret);
    return Format.decodeBigInt(parameters.E.modPow(alice_secret, parameters.N));
};

// Bob uses the masked value from Alice to blind her to the choice he has made
OT.blind = function blind (parameters, bob_secret, u8_masked, choice) {
    bob_secret = Format.encodeBigInt(bob_secret);
    var masked = Format.encodeBigInt(u8_masked);
    return Format.decodeBigInt(choice?
        masked.multiply(parameters.E.modPow(bob_secret, parameters.N)):
        parameters.E.modPow(bob_secret, parameters.N));
};

// Given Alice' keys and Bob's blinded value, return two encryption keys to be used for your two messages
OT.unmask = function unmask (parameters, alice_secret, u8_masked, u8_blinded) {
    alice_secret = Format.encodeBigInt(alice_secret);
    var masked = Format.encodeBigInt(u8_masked);
    var blinded = Format.encodeBigInt(u8_blinded);
    return [
        blinded.modPow(alice_secret, parameters.N),
        blinded.divide(masked).modPow(alice_secret, parameters.N)
    ].map(function (N) {
        return Nacl.hash(Format.decodeBigInt(N));
    });
};

// after Alice has used Bob's blinded choice to derive two keys, Bob unblinds to derive a key that matches at most one of the two which Alice produced
OT.unblind = function unblind (parameters, bob_secret, u8_masked) {
    bob_secret = Format.encodeBigInt(bob_secret);
    var masked = Format.encodeBigInt(u8_masked);
    return Nacl.hash(Format.decodeBigInt(masked.modPow(bob_secret, parameters.N)));
};

