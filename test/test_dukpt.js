var dukpt = require("../dukpt");

var bdk = Buffer.from("0123456789ABCDEFFEDCBA9876543210", "hex");

var test_cases = 
[
	{
		ksn: "FFFF9876543210E00001",
		std: "042666B49184CFA368DE9628D0397BC9",
		pin: "042666B49184CF5C68DE9628D0397B36",
		mac: "042666B4918430A368DE9628D03984C9",
		data:"448D3F076D8304036A55A3D7E0055A78",
	},

	{
		ksn: "FFFF9876543210E00002",
		std: "C46551CEF9FD24B0AA9AD834130D3BC7",
		pin: "C46551CEF9FD244FAA9AD834130D3B38",
		mac: "C46551CEF9FDDBB0AA9AD834130DC4C7",
		data:"F1BE73B36135C5C26CF937D50ABBE5AF",
	},

	{
		ksn: "FFFF9876543210E00003",
		std: "0DF3D9422ACA56E547676D07AD6BADFA",
		pin: "0DF3D9422ACA561A47676D07AD6BAD05",
		mac: "0DF3D9422ACAA9E547676D07AD6B52FA",
		data:"EEEEF522C67239E4A2A65FEBF4C511F4",
	},

	{
		ksn: "FFFF9876543210E00004",
		std: "279C0F6AEED0BE652B2C733E1383AE91",
		pin: "279C0F6AEED0BE9A2B2C733E1383AE6E",
		mac: "279C0F6AEED041652B2C733E13835191",
		data:"BCF2610997C3AC3C5F13AE965A1B773B",
	},
	{
		ksn: "FFFF9876543210E00005",
		std: "5F8DC6D2C845C125508DDC048093B83F",
		pin: "5F8DC6D2C845C1DA508DDC048093B8C0",
		mac: "5F8DC6D2C8453E25508DDC048093473F",
		data:"F3054D8B7471284BDB4EE18AFC3B091B",
	},
];


function runTest()
{
	console.log("total test case: " + test_cases.length);
	for(var i=0; i<test_cases.length; i++)
	{
		console.log("testing case #"+(i+1));

		var ksn = Buffer.from(test_cases[i].ksn, "hex");

		var key_std = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_STD);
		var key_pin = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_PIN);
		var key_mac = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_MAC);
		var key_data = dukpt.GetKey(bdk, ksn, dukpt.KEY_TYPE_DATA);

		if(key_std.toString("hex").toUpperCase() == test_cases[i].std) 
			console.log("derive std from bdk for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive std from bdk for ksn: " + test_cases[i].ksn + " failed ...xxx");


		if(key_pin.toString("hex").toUpperCase() == test_cases[i].pin) 
			console.log("derive pin from bdk for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive pin from bdk for ksn: " + test_cases[i].ksn + " failed ...xxx");


		if(key_mac.toString("hex").toUpperCase() == test_cases[i].mac) 
			console.log("derive mac from bdk for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive mac from bdk for ksn: " + test_cases[i].ksn + " failed ...xxx");


		if(key_data.toString("hex").toUpperCase() == test_cases[i].data) 
			console.log("derive data from bdk for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive data from bdk for ksn: " + test_cases[i].ksn + " failed ...xxx");



		var ipek = dukpt.GetIPEK(bdk, ksn);
		var key_std = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_STD);
		var key_pin = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_PIN);
		var key_mac = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_MAC);
		var key_data = dukpt.GetKeyFromIPEK(ipek, ksn, dukpt.KEY_TYPE_DATA);

		if(key_std.toString("hex").toUpperCase() == test_cases[i].std) 
			console.log("derive std from ipek for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive std from ipek for ksn: " + test_cases[i].ksn + " failed ...xxx");

		if(key_pin.toString("hex").toUpperCase() == test_cases[i].pin) 
			console.log("derive pin from ipek for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive pin from ipek for ksn: " + test_cases[i].ksn + " failed ...xxx");


		if(key_mac.toString("hex").toUpperCase() == test_cases[i].mac) 
			console.log("derive mac from ipek for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive mac from ipek for ksn: " + test_cases[i].ksn + " failed ...xxx");


		if(key_data.toString("hex").toUpperCase() == test_cases[i].data) 
			console.log("derive data from ipek for ksn: " + test_cases[i].ksn + " pass ....");
		else 
			console.log("derive data from ipek for ksn: " + test_cases[i].ksn + " failed ...xxx");
	}

	
}


runTest();


