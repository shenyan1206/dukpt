var dukpt = require("./dukpt");

var bdk = Buffer.from("0123456789ABCDEFFEDCBA9876543210", "hex");
var ksn = Buffer.from("FFFF9876543210E00011", "hex");

//var ipek = dukpt.GetIPEK(bdk, ksn);
//console.log("IPEK:" + ipek.toString("hex"));

var key_std = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_STD);
var key_pin = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_PIN);
var key_mac = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_MAC);
var key_data = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_DATA);

console.log("key std:" + key_std.toString("hex"));
console.log("key pin:" + key_pin.toString("hex"));
console.log("key mac:" + key_mac.toString("hex"));
console.log("key data:" + key_data.toString("hex"));