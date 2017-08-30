# dukpt
DUKPT key manage for nodejs. Based on ANS X9.24-1:2009

find the examples in example.js

supported key type: STD, MAC, PIN, DATA.

STD has no variants applied.

MAC, PIN has variants.

DATA has variants, and also has addtional encryption.


npm start  # to start the example.js

npm test   # to launch the test cases


//example

var dukpt = require("@shenyan1206/dukpt");

var bdk = Buffer.from("0123456789ABCDEFFEDCBA9876543210", "hex");
var ksn = Buffer.from("FFFF9876543210E00011", "hex");

var key_std = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_STD);
var key_pin = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_PIN);
var key_mac = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_MAC);
var key_data = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_DATA);

console.log("key std:" + key_std.toString("hex"));
console.log("key pin:" + key_pin.toString("hex"));
console.log("key mac:" + key_mac.toString("hex"));
console.log("key data:" + key_data.toString("hex"));

console.log("===================================");

var ipek = dukpt.GetIPEK(bdk, ksn);
console.log("IPEK:" + ipek.toString("hex"));

var key_std = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_STD);
var key_pin = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_PIN);
var key_mac = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_MAC);
var key_data = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_DATA);

console.log("key std:" + key_std.toString("hex"));
console.log("key pin:" + key_pin.toString("hex"));
console.log("key mac:" + key_mac.toString("hex"));
console.log("key data:" + key_data.toString("hex"));
