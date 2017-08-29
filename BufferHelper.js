//constructor
const OPERATOR_AND = 1;
const OPERATOR_OR = 2;
const OPERATOR_XOR = 3;


function BufferHelper(){};


//private functions
function operator(buffer, mask, operator, newBuffer)
{
	if(buffer.length != mask.length) throw new Error("BufferHelper Operator AND, Invalid data length");

	var result;
	if(newBuffer) result = Buffer.alloc(buffer.length); //new buffer
	else result = buffer;  //old buffer


	for(var i=0; i<buffer.length; i++)
	{
		switch(operator)
		{
			case OPERATOR_AND:
				result[i] = buffer[i] & mask[i];
				break;
			case OPERATOR_OR:
				result[i] = buffer[i] | mask[i];
				break;
			case OPERATOR_XOR:
				result[i] = buffer[i] ^ mask[i];
				break;
			default:
				throw new Error("Unknow Operator in BufferHelper");

		}
	}	
	return result;
}

//public functions

//modify buffer directly
BufferHelper.prototype.AND = function(buffer, mask) 
{
	return operator(buffer, mask, OPERATOR_AND, false);
}
BufferHelper.prototype.OR = function(buffer, mask) 
{
	return operator(buffer, mask, OPERATOR_OR, false);
}
BufferHelper.prototype.XOR = function(buffer, mask) 
{
	return operator(buffer, mask, OPERATOR_XOR, false);
}


//create new buffer, modify the new buffer only
BufferHelper.prototype.AND_new = function(buffer, mask) 
{
	return operator(buffer, mask, OPERATOR_AND, true);
}
BufferHelper.prototype.OR_new = function(buffer, mask) 
{
	return operator(buffer, mask, OPERATOR_OR, true);
}
BufferHelper.prototype.XOR_new = function(buffer, mask) 
{
	return operator(buffer, mask, OPERATOR_XOR, true);
}


/* ************************************************************************
SINGLETON CLASS DEFINITION
************************************************************************ */
BufferHelper.instance = null;
/**
 * Singleton getInstance definition
 * @return singleton class
 */
BufferHelper.getInstance = function(){
    if(this.instance === null){
        this.instance = new BufferHelper();
    }
    return this.instance;
}
 
module.exports = BufferHelper.getInstance();
