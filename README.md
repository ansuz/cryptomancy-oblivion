# Cryptomancy-oblivion

This module implements primitives for [oblivious transfer](https://en.wikipedia.org/wiki/Oblivious_transfer), an interactive protocol which allows one party to choose strictly one out of some number of messages without revealing to the sender which message was chosen.

Based on [kevinejohn's 'oblivious-transfer'](https://github.com/kevinejohn/oblivious-transfer) but with different dependencies and major changes to the API.

## DISCLAIMER

I have no idea how safe this is for actual use. I'm personally using it for implementing peer-to-peer games where long-term security is not a concern.

I strongly recommend against using this module for anything other than experimentation.

## Use

`npm install --save cryptomancy-oblivion`

```javascript
var OT = require("cryptomancy-oblivion");

// Alice has two messages, which can be anything
// To make it interesting, suppose they are codes which unlock prizes of different values
// Bob would like to have both messages, but Alice is forcing him to choose
var Messages = [
    'The key to door number 1',
    'The key to door number 2'
];

var Choice = 0; // 0 or 1

// the protocol uses some public parameters
// an exponent and a modulus as in RSA
var Public = OT.genkeys();

// Alice and Bob each need a 32-byte secret, generated however you like
// 'cryptomancy-source' implements various flavours of randomness, so you can use that
// it returns Uint8Arrays
var Source = require("cryptomancy-source");

var makeSecret = function () {
    return Source.bytes.secure()(32);
};

var alice_secret = makeSecret();
var bob_secret = makeSecret();

// Alice can use the public parameters to mask her secret such that she can share it with Bob
// without him learning what it is
var masked = OT.mask(Public, alice_secret);

// Bob wants what's behind Door number 1
// he can 'blind' his choice by using his secret and combining it with Alice's masked value
// Alice will use this blinded value, but she won't be able to learn which of the two doors Bob chose
var blinded = OT.blind(Public, bob_secret, masked, Choice);

// given Bob's blinded value and using her own secrets, Alice can derive two hashes
// you can derive encryption keys from these hashes. How you do so will depend on the cipher you want to use
var unmasked = OT.unmask(Public, alice_secret, masked, blinded); // an array of two hashes

// Alice can now use these two keys to encrypt the two messages
// there are a lot of ciphers you could use here, but one is provided which should work just fine
var Crypto = require("cryptomancy-oblivion/crypto");

// this cipher assumes a key made of 32 Uint8s
var Encrypted = unmasked.map(function (hash, i) {
    return Crypto.encrypt(hash.subarray(0, 32), Messages[i]);
});

// The trick is that Bob will be able to reproduce only one of the two keys
// corresponding to the choice he made.
var bob_key = OT.unblind(Public, bob_secret, masked).subarray(0, 32);

// Now he can try to decrypt both values, but only the first will work
var decrypted = Crypto.decrypt(bob_key, Encrypted[0]);
assert.equal(decrypted, Messages[0]);
```

## Tests

```
npm test
```
