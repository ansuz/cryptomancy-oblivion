/* globals Uint8Array */
var assert = require("assert");
var Source = require("cryptomancy-source");

// Use whatever crypto you like, I guess
// The OT part is mostly about key exchange
var Crypto = require("./crypto");

var ot = require('.');

var gensecret = function () {
    return Source.bytes.secure()(32);
};

var hashToKey = function (hash) {
    return hash.subarray(0, 32);
};

var Messages = [
    'Alice did it',
    'Bob did it',
];

// generate some public values (an exponent and a modulus)
console.log("Generating public parameters");
var Public = ot.genkeys();

[0, 1, 2, 3, 4, 5].forEach(function (n) {
    console.log("Running test #%s", n);

    var Choice = n % 2;
    // Alice also has a secret that she won't tell Bob
    var alice_secret = gensecret();

    // Alice uses her secret and the public values to create a mask
    // she can freely reveal this to Bob
    var masked = ot.mask(Public, alice_secret);

    // Bob also keeps a secret
    var bob_secret = gensecret();
    // he uses it create a blind
    // it's used to choose one of Alice's values without revealing which one
    var blinded = ot.blind(Public, bob_secret, masked, Choice);

    // Alice uses her mask and Bob's blind to derive two encryption keys
    // she uses them to encrypt her two messages, which she can then reveal to Bob
    var unmasked = ot.unmask(Public, alice_secret, masked, blinded);
    var Encrypted = unmasked.map(function (key, i) {
        return Crypto.encrypt(hashToKey(key), Messages[i]);
    });

    // Bob has the ciphertexts, only one of which he should be able to decrypt
    // he should know which one since he knows what he chose for his blind.
    var bob_key = hashToKey(ot.unblind(Public, bob_secret, masked));
    var Decrypted = Encrypted.map(function (ciphertext) {
        return Crypto.decrypt(bob_key, ciphertext);
    });

    // the option you chose should have been decrypted
    assert.equal(Decrypted[Choice], Messages[Choice]);
    // the option you neglected should have failed to decrypt
    assert.equal(null, Decrypted[(Choice +1) % 2]);
});
