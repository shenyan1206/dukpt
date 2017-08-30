var DUKPT_Internal = require("./dukpt_internal");
var KeyType = require("./KeyType");

//constructor
function DUKPT(){
	this.KEY_TYPE_STD = KeyType.KEY_TYPE_STD;
	this.KEY_TYPE_PIN = KeyType.KEY_TYPE_PIN ;
	this.KEY_TYPE_MAC = KeyType.KEY_TYPE_MAC;
	this.KEY_TYPE_DATA = KeyType.KEY_TYPE_DATA;
};


//public functions
DUKPT.prototype.GetIPEK = function(bdk, ksn) 
{
	dukpt_internal = new DUKPT_Internal();

	return dukpt_internal.GetIPEK(bdk, ksn);
}

DUKPT.prototype.GetKey = function(bdk, ksn, key_type=KeyType.KEY_TYPE_STD) 
{
	dukpt_internal = new DUKPT_Internal();

	return dukpt_internal.GetKey(bdk, ksn, key_type);
}


DUKPT.prototype.GetKeyFromIPEK = function(ipek, ksn, key_type=KeyType.KEY_TYPE_STD) 
{
	dukpt_internal = new DUKPT_Internal();

	return dukpt_internal.GetKeyFromIPEK(ipek, ksn, key_type);
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
