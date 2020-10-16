const {EthereumAccount, Web3Connection, EthereumContract, util} = require("arc-web3");
const rlp = require("../lib_imported/rlp.js");
const {keccak256} = require("keccak-wasm");
const assert = function(e, msg){
	if (!e){
		throw new Error(msg);
	}
}
let secp256k1 = null;
const GAS_LIMIT = 12400000;
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
		if (typeof privKey == "string" && /^0x[0-9a-f]{40}$/i.test(privKey)){
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
		
		const hash = keccak256(pubKey.slice(pubKey.length - 64));
		const address = util.toChecksumAddress(hash.substring(hash.length - 40), true);
		super(connection,address);
		this.privKey = privKey;
		this.pubKey = pubKey;
		this.chainID = null;
	}
	async discoverChainID() {
		this.chainID = await this._connection.networkID();
	}
	sign(data,addToV){
		addToV = addToV | 0;
		const hash = keccak256(data, false);
		const stuff = secp256k1.signMessageHashRecoverableCompact(this.privKey,hash);
		return {
			messageHash: hash,
			v: stuff.recoveryId + addToV,
			r: Buffer.from(stuff.signature.subarray(0,32)),
			s: Buffer.from(stuff.signature.subarray(32))
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
		txData.data = txData.data || Buffer.alloc(0);
		assert(txData.gasPrice != null, "txData.gasPrice isn't set");
		assert(txData.gasLimit != null, "txData.gasLimit isn't set");
		txData.value = txData.value || 0;
		txData.v = txData.chainID || this.chainID;
		if (txData.v == null){
			throw new Error("The chain ID is unknown. Please call EthereumAccountSignable.discoverChainID() before signing transactions");
		}
		delete txData.chainID;
		txData.r = Buffer.alloc(0);
		txData.s = Buffer.alloc(0);
		
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

	// Same reason as above with the "async" part
	async signData(data){
		let sigObj = this.sign(
			Buffer.concat([
				Buffer.from("\x19Ethereum Signed Message:\n" + Buffer.byteLength(data).toString(), "ascii"),
				Buffer.from(data)
			]), 27
		);
		sigObj.signature = "0x" + sigObj.r.toString("hex") + sigObj.s.toString("hex") + (sigObj.v < 16 ? "0" : "") + sigObj.v.toString(16);
		return sigObj;
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
		if(txData.to instanceof EthereumAccount || txData.to instanceof EthereumContract){
			txData.to = txData.to.address;
		}
		if (txData.gasLimit == null){
			txData.gasLimit = await this._connection.estimateGas({
				from: this.address,
				to: txData.to,
				data: txData.data,
				gasPrice: txData.gasPrice,
				value: txData.value || 0n
			});
			if (txData.gasLimit > 21000){
				txData.gasLimit *= 1.25;
				txData.gasLimit |= 0;
				if (txData.gasLimit > GAS_LIMIT){
					txData.gasLimit = GAS_LIMIT;
				}
			}
		}
		let txHash = await this._connection.sendRawTransaction(this.signTransaction(txData).rawTransaction);
		this.nonce += 1;
		return txHash;
	}
}
EthereumAccountSignable.prototype.signMessage = EthereumAccountSignable.prototype.signData;
module.exports = {
	EthereumAccountSignable,
	InitializeEthereumAccountSignable: async (s) => {
		secp256k1 = await s;
	},
	rlp
}
