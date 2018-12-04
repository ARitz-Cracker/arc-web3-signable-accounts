const {EthereumAccount, Web3Connection, EthereumContract} = require("arc-web3");
const rlp = require("../lib_imported/rlp.js");
const BufferLib = require("arc-bufferlib");
const keccak256 = require('js-sha3').keccak256;
const assert = function(e, msg){
	if (!e){
		throw new Error(msg);
	}
}
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
	// pubKey is an internal value, intended to be used by other functions which already provide a public key by default.
	constructor(connection, privKey, pubKey){
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
		if (pubKey == null){
			pubKey = secp256k1.derivePublicKeyUncompressed(privKey);
		}else if(pubKey.length == 33){
			pubKey = secp256k1.uncompressPublicKey(pubKey);
		}else if(pubKey.length != 65){
			throw new Error("Invalid public key");
		}
		
		let hash = keccak256(pubKey.slice(pubKey.length - 64));
		let address = "0x"+hash.substring(hash.length - 40); // TODO: Generate checksummed value
		super(connection,address);
		this.privKey = privKey;
		this.pubKey = pubKey;

		this.nonce = 0;
		this.chainID = null;
	}
	async updateNonce(){
		let nonce = await this._connection.getTransactionCount(this.address);
		if (nonce > this.nonce){
			this.nonce = nonce;
		}
		return this.nonce;
	}
	async discoverChainID() {
		this.chainID = await this._connection.networkID();
	}
	sign(data,addToV){
		addToV = addToV | 0;
		let hash = BufferLib.from(keccak256.arrayBuffer(data));
		let stuff = secp256k1.signMessageHashRecoverableCompact(this.privKey,hash);
		return {
			messageHash: hash,
			v: stuff.recoveryId + addToV,
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
			value: 0
		}
		*/
		assert(txData.nonce != null, "txData.nonce isn't set");
		assert(txData.to != null || txData.data != null, "txData.to isn't set");
		txData.data = txData.data || BufferLib.newBuffer(0);
		assert(txData.gasPrice != null, "txData.gasPrice isn't set");
		assert(txData.gasLimit != null, "txData.gasLimit isn't set");
		txData.value = txData.value || 0;
		txData.v = txData.chainID || this.chainID;
		if (txData.v == null){
			throw new Error("The chain ID is unknown. Please call EthereumAccountSignable.discoverChainID() before signing transactions");
		}
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
	
	async sendTransaction(txData){
		if (this.chainID == null){
			await this.discoverChainID();
			txData.chainID = this.chainID;
		}
		
		if (txData.nonce == null){
			await this.updateNonce();
			txData.nonce = this.nonce;
		}
		if (txData.gasPrice == null){
			txData.gasPrice = await this._connection.gasPrice();
		}
		let txHash = await this._connection.sendRawTransaction(this.signTransaction(txData).rawTransaction);
		this.nonce += 1;
		return txHash;
	}
	
	async transfer(account, amount, gasPrice, gasLimit, nonce){
		if (account instanceof EthereumAccount){
			account = account.address;
		}else if (account instanceof EthereumContract){
			account = account._jsproperties.account.address;
		}
		if (gasPrice == null){
			gasPrice = await this._connection.gasPrice();
		}
		if (gasLimit == null){
			gasLimit = await this._connection.estimateGas({
				from: this.address,
				to: account,
				gasPrice: gasPrice,
				value: amount
			});
			if (gasLimit > 21000){
				gasLimit *= 1.5;
			}
		}
		return this.sendTransaction({
			to: account,
			gasPrice,
			gasLimit,
			value: amount,
			nonce
		});
	}
	
	balance(blockNumber){
		return this._connection.getBalance(this.address,blockNumber);
	}
}

module.exports = {
	EthereumAccountSignable,
	InitializeEthereumAccountSignable: async (s) => {
		secp256k1 = await s;
	},
	rlp
}

