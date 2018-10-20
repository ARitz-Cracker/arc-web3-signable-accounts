const {EthereumAccount, Web3Connection} = require("arc-web3");
const BigNumber = require("bignumber.js");
const keccak256 = require('js-sha3').keccak256;
let secp256k1 = null;

const fieldsToRLPArray = [
	"nonce",
	"gasPrice",
	"gasLimit",
	"to",
	"value",
	"data",
	"v", // Is set as the chain ID
	"r",
	"s"
]

class EthereumAccountSignable extends EthereumAccount{
	constructor(connection,privKey){
		if (secp256k1 == null){
			throw new Error("secp256k1 isn't initialized yet.");
		}
		if (typeof privKey == "string" && /^0x[0-9a-f]{40}$/i.test(privKey)){ // TODO: Checksum check
			throw new TypeError("This object is for making signable accounts, not readOnly accounts");
		}
		
		if (!(privKey instanceof Uint8Array)){
			throw new TypeError("private key argument must be a Buffer or Uint8Array");
		}
		if(privKey.length != 32){
			throw new TypeError("Private keys must be 32 bytes in length.");
		}
		let pubKey = secp256k1.derivePublicKeyUncompressed(privKey);
		
		let hash = keccak256(pubKey.slice(pubKey.length - 64));
		let address = "0x"+hash.substring(hash.length - 40); // TODO: Generate checksummed value
		super(connection,address);
		this.privKey = privKey;
		this.pubKey = pubKey;
		
	}
	sign(data,addToV){
		addToV = addToV | 0;
		let hash = BufferLib.from(keccak256.arrayBuffer(data));
		let stuff = secp256k1.signMessageHashRecoverableCompact(this.privKey,hash);
		return {
			messageHash: hash,
			v: stuff.recovery + addToV,
			r: stuff.signature.slice(0,32),
			s: stuff.signature.slice(32)
		}
	}
	signTransaction(txData){
		/*
		let txData = {
			nonce: 100,
			to:"0xc7029ed9eba97a096e72607f4340c34049c7af48",
			data:"0x91c05b0b0000000000000000000000000000000000000000000000000000000000000063",
			gasPrice: 1e11,
			gasLimit: 3000000,
			value: 0,
			chainID
		}
		*/
		txData.nonce = txData.nonce || BufferLib.from([1]);
		txData.to = txData.to || BufferLib.newBuffer(20);
		txData.data = txData.data || BufferLib.newBuffer(0);
		txData.gasPrice = txData.gasPrice || BufferLib.from([1]);
		txData.gasLimit = txData.gasLimit || BufferLib.from([1]);
		txData.value = txData.value || 0;
		txData.v = txData.chainID || 1;
		delete txData.chainID;
		txData.r = BufferLib.newBuffer(0);
		txData.s = BufferLib.newBuffer(0);
		
		let RLPArr = [];
		for (let i=0;i<fieldsToRLPArray.length;i+=1){
			RLPArr[i] = txData[fieldsToRLPArray[i]];
		}
		let RLPEncoded = rlp.encode(RLPArr);
		
		let signature = this.sign(RLPEncoded,txData.v * 2 + 35);
		
		RLPArr[6] = signature.v;
		RLPArr[7] = signature.r;
		RLPArr[8] = signature.s;
		
		signature.rawTransaction = rlp.encode(RLPArr);
		return signature;
	}
	
	sendTransaction(tx){
		throw new Error("I didn't call Web3Connection.sendRawTransaction before I went to bed.");
	}
	
	transfer(account,amount){
		throw new Error("I didn't finish EthereumAccountSignable.sendTransaction before I went to bed.");
	}
	
	balance(blockNumber){
		return this._connection.getBalance(this.address,blockNumber);
	}
}

let initialize = async function(){
	secp256k1 = await require("bitcoin-ts").instantiateSecp256k1();
}

module.exports = {
	EthereumAccountSignable:EthereumAccountSignable
}

