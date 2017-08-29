var crypto = require("crypto");
var BufferHelper = require("./BufferHelper");
var CryptoHelper = require("./CryptoHelper");


//private variables
var encrypt_ctr, future_key_reg, initKSN, LRC_reg, cArray;


//constructor
function DUKPT(){
	this.KEY_TYPE_STD = 0;
	this.KEY_TYPE_PIN = 1;
	this.KEY_TYPE_MAC = 2;
	this.KEY_TYPE_DATA = 3;
};

function init()
{

	encrypt_ctr = 0;
	future_key_reg = [];
	initKSN = Buffer.alloc(10);
	LRC_reg = Buffer.alloc(21);
	cArray = Buffer.from("C0C0C0C000000000C0C0C0C000000000", "hex");

}


//private functions
function LoadInitKey(pInitKey, pInitKSN)
{
	var cryptoReg = Buffer.alloc(16);

	//init all future key registers to zeros
	for(var i=0; i<21; i++)
	{
		future_key_reg[i] = Buffer.alloc(16);
		LRC_reg[i] = 0;
	}

	//clear encryption coutner
	encrypt_ctr = 0;
	var currKeyPtr = 20;

	//store initial key in future reg#21, ie index=20
	future_key_reg[currKeyPtr] = pInitKey;
	LRC_reg[currKeyPtr] = CalcLRC(pInitKey);

	initKSN = pInitKSN;
	UpdateKSN(encrypt_ctr, initKSN);

	var shiftReg = Buffer.from("00100000", "hex").readInt32BE();
	PropogateKeys(cryptoReg, shiftReg, currKeyPtr);

	encrypt_ctr++;
	UpdateKSN(encrypt_ctr, initKSN);

}

function UpdateKSN(encCtnr, pKsnReg)
{

	var encCtnr_bin = Buffer.alloc(4);
	encCtnr_bin.writeInt32BE(encCtnr);
	BufferHelper.AND(encCtnr_bin, Buffer.from("001FFFFF","hex"));
	BufferHelper.AND(pKsnReg, Buffer.from("FFFFFFFFFFFFFFE00000","hex"));

	BufferHelper.OR(pKsnReg.slice(6,10), encCtnr_bin);
}

/*
cryptoReg   :  16 bytes, buffer, by ref
shiftReg 	:  int32u
ksnReg 		:  10 bytes, buffer, by ref
*/
function InitCryptoReg(cryptoReg, shiftReg, ksnReg)
{
	cryptoReg.fill(0, 0, 8);
	cryptoReg.writeInt32BE(shiftReg, 4);
	
	BufferHelper.OR(cryptoReg.slice(0, 8), ksnReg.slice(2,10));
}

function PropogateKeys(cryptoReg, shiftReg, currKeyPtr)
{

	while(shiftReg > 0)
	{
		InitCryptoReg(cryptoReg, shiftReg, initKSN);
		NonReversibleKeyGen(cryptoReg, future_key_reg[currKeyPtr]);

		var posSR = GetSetBitPos(shiftReg);
		var swap1 = posSR % 2;

		var posEC = GetSetBitPos(encrypt_ctr);
		var swap2 = posEC % 2;

		if(encrypt_ctr > 0) swap2 ^= 1;
		else swap2 = 0;

		if(swap2 > 0) swap1 ^= 1;

		var cr1 = cryptoReg.slice(0, 8);
		var cr2 = cryptoReg.slice(8, 16);
		var fk;
		if(swap1 > 0) fk = Buffer.concat([cr2, cr1]);
		else fk = Buffer.concat([cr1, cr2]); 

		future_key_reg[posSR] = fk;

		LRC_reg[posSR] = CalcLRC(fk);

		shiftReg >>=1;

		
	}

}


/*
cryptoReg : 16 bytes, buffer, by ref
key : 		16 bytes, buffer, by ref
*/

function NonReversibleKeyGen(cryptoReg, key)
{

	var cr1 = cryptoReg.slice(0, 8);
	var cr2 = cryptoReg.slice(8, 16);

	var keyL = key.slice(0, 8);
	var keyR = key.slice(8, 16);

	cr2 = BufferHelper.XOR_new (cr1, keyR);
	//single des encryption
	cr2 = CryptoHelper.des_enc_ecb(keyL, cr2);
	cr2 = BufferHelper.XOR(cr2, keyR);

	BufferHelper.XOR(key, cArray);
	keyL = key.slice(0, 8);
	keyR = key.slice(8, 16);

	cr1 = BufferHelper.XOR_new(cr1, keyR);
	//single des encryption
	cr1 = CryptoHelper.des_enc_ecb(keyL, cr1);
	cr1 = BufferHelper.XOR(cr1, keyR);
	
	//combin cr1 cr2
	cr1.copy(cryptoReg, 0, 0, 8);
	cr2.copy(cryptoReg, 8, 0, 8);

}

/*
encrypt_counter : int32u
pCurrKSN		: 10 bytes, buffer, by ref
pCurrKey		: 16 bytes, buffer, by ref
PinKey 			: int32u
*/
function EncryptPIN(encrypt_counter, pCurrKSN, pCurrKey, key_type=0)
{

	//PinKey always -
	var cryptoReg = Buffer.alloc(16);
	var shiftReg = 0;
	var MAX_EC = Buffer.from("00200000", "hex").readInt32BE();
	if(encrypt_ctr > MAX_EC)
	{
		throw new Error("DUKPT Error, Not Initialized")
	}

	var position = 0;
	var currKeyPtr = 0;
	while(true)
	{
		position = GetSetBitPos(encrypt_counter);
		shiftReg = SetBit(shiftReg, position);

		currKeyPtr = position;
		future_key_reg[currKeyPtr].copy(pCurrKey, 0, 0, 16);

		if(LRC_reg[currKeyPtr] == CalcLRC(pCurrKey)) break; //ok, found a valid key
		else encrypt_ctr += shiftReg;
	}//end while

	encrypt_ctr = encrypt_counter;

	UpdateKSN(encrypt_ctr, initKSN);

	var mask;
	if(key_type == 0)  //STD, no mask
		mask = Buffer.from("0000 0000 0000 0000   0000 0000 0000 0000".replace(/ /g, ''), "hex");
	else if(key_type == 1) //PIN
		mask = Buffer.from("0000 0000 0000 00FF   0000 0000 0000 00FF".replace(/ /g, ''), "hex");
	else if(key_type == 2) //MAC
		mask = Buffer.from("0000 0000 0000 FF00   0000 0000 0000 FF00".replace(/ /g, ''), "hex");
	else if(key_type == 3) //DATA
		mask = Buffer.from("0000 0000 00FF 0000   0000 0000 00FF 0000".replace(/ /g, ''), "hex"); 

	BufferHelper.XOR(pCurrKey, mask);

	if(key_type == 3) //DATA, addtional steps
	{
		var pCurrKeyL = pCurrKey.slice(0, 8);
		var pCurrKeyR = pCurrKey.slice(8, 16);

		console.log("key: " + pCurrKey.toString("hex"));
		console.log("data: " + pCurrKeyL.toString("hex"));

		pCurrKeyL = CryptoHelper.tdes_enc_ecb(pCurrKey, pCurrKeyL);
		pCurrKeyR = CryptoHelper.tdes_enc_ecb(pCurrKey, pCurrKeyR);

		pCurrKeyL.copy(pCurrKey, 0, 0, 8);
		pCurrKeyR.copy(pCurrKey, 8, 0, 8);

	}

	initKSN.copy(pCurrKSN, 0, 0, 10); //return current ksn

	//generate new key
	GenNewKeys(cryptoReg, shiftReg, currKeyPtr);
	
}

/*
cryptoReg :  16 bytes, buffer, pass by ref
shiftReg  :  int32u
currKeyPtr:  int32u 	
*/
function GenNewKeys(cryptoReg, shiftReg, currKeyPtr)
{
	if(GetNumOfOnes(encrypt_ctr) < 10)
	{
		shiftReg >>= 1;

		PropogateKeys(cryptoReg, shiftReg, currKeyPtr);

		//erase from memory
		future_key_reg[currKeyPtr].fill(0);
		LRC_reg[currKeyPtr] = 0xFF;

		encrypt_ctr++;
		UpdateKSN(encrypt_ctr, initKSN);
	}
	else
	{
		//earse from memory
		future_key_reg[currKeyPtr].fill(0);
		LRC_reg[currKeyPtr] = 0xFF;

		encrypt_ctr += shiftReg;
		UpdateKSN(encrypt_ctr, initKSN);
	}
}

/*
encCntr  : int32u
onebit   : int32u
*/
function ChangeCounter(encCntr, onebit)
{
	var mask = Buffer.from("00100000", "hex").readInt32BE();
	var tmp_mask = mask;
	var numOfOnes = 0;

	for(var i=0; i<21; i++)
	{
		if(numOfOnes >= onebit) break;
		if(i!=0)
		{
			mask >>= 1;
			tmp_mask += mask;
		}
		if((encCntr & mask) > 0) numOfOnes++;
	}
	encCntr &= tmp_mask;

	return encCntr;
}

/*
ksn  : 10 bytes, buffer
*/
function GetCounterFromKSN(ksn)
{
	return BufferHelper.AND_new(ksn.slice(6,10), Buffer.from("001FFFFF", "hex")).readInt32BE(); //right most 21 bits, 4 bytes to convert to int32u
}

/*
key : 16 bytes, buffer
*/
function CalcLRC(key)
{
	var lrc = key[0];
	for(var i=1; i<key.length; i++) lrc ^= key[i];
	return lrc;
}


/*
encCntr : int32u, number format
*/
function GetNumOfOnes(encCntr)
{
	var numOfOnes = 0;
	for(var i=0, mask=1; i<21; i++, mask<<=1)
	{
		if((encCntr & mask) > 0 ) numOfOnes++;
	}
	return numOfOnes;
}


/*
reg : int32u, number format
*/
function GetSetBitPos(reg)
{
	for(var i=0, mask=1; i<21; i++, mask<<=1)
	{
		if((reg & mask)>0) return ((21-1) -i);
	}
	return -1;
}

/*
reg : int32u, number format
pos : int32u, number format, positon of right most bit 1
*/
function SetBit(reg, pos)
{
	reg |= (1 << ((21-1)-pos));
	return reg;
}




//public functions
DUKPT.prototype.GetIPEK = function(bdk, ksn) 
{
	if(bdk.length != 16) throw new Error("Invalid BDK length, expect 16, received: " + bdk.length);
	if(ksn.length != 10) throw new Error("Invalid KSN length, expect 10, received: " + ksn.length);

	var bdk_masked = BufferHelper.XOR_new(bdk, cArray);
	var iksn = BufferHelper.AND_new(ksn, Buffer.from("FFFFFFFFFFFFFFE00000", "hex"));

	var ksn_left8 = iksn.slice(0, 8);
	
	var ipek_left8 = CryptoHelper.tdes_enc_ecb(bdk, ksn_left8);
	var ipek_right8 = CryptoHelper.tdes_enc_ecb(bdk_masked, ksn_left8);

	return Buffer.concat([ipek_left8, ipek_right8]);
}

DUKPT.prototype.GetKey = function(bdk, ksn, key_type) 
{
	init();

	ksn = Buffer.concat([ksn]);

	if(bdk.length != 16) throw new Error("Invalid BDK length, expect 16, received: " + bdk.length);
	if(ksn.length != 10) throw new Error("Invalid KSN length, expect 10, received: " + ksn.length);
	if(key_type > 4 || key_type <0) throw new Error("Invalid key type");

	var counter = GetCounterFromKSN(ksn);
	BufferHelper.AND(ksn, Buffer.from("FFFFFFFFFFFFFFE00000", "hex"));

	var ipek = this.GetIPEK(bdk, ksn);

	LoadInitKey(ipek, ksn); //by reference, update buffer directly


	var m_cryptoKey = Buffer.alloc(16);
	var k=1;
	do
	{
		var tmp = ChangeCounter(counter, k);

		EncryptPIN(tmp, ksn, m_cryptoKey, key_type);
		k++;

	}while (k <= GetNumOfOnes(counter));


	return m_cryptoKey;
}



/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
DUKPT.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
DUKPT.getInstance = function(){
    if(this.instance === null){
        this.instance = new DUKPT();
    }
    return this.instance;
}
 
module.exports = DUKPT.getInstance();
