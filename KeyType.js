function KeyType(){
	this.KEY_TYPE_STD = 0;
	this.KEY_TYPE_PIN = 1;
	this.KEY_TYPE_MAC = 2;
	this.KEY_TYPE_DATA = 3;
}


/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
KeyType.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
KeyType.getInstance = function(){
    if(this.instance === null){
        this.instance = new KeyType();
    }
    return this.instance;
}
 
module.exports = KeyType.getInstance();