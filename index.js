import {
  bufferToHex,
  generateAddress,
  isValidPrivate,
  privateToPublic,
  publicToAddress,
  toChecksumAddress,
  toBuffer
} from "ethereumjs-util";
import { encryptPrivateKey, generatePrivateKey } from "./lib/crypto";
import { v4 } from "uuid";

export default class Address {
  constructor(privateKey) {
    let _privateKey;
    if (privateKey !== undefined) {
      _privateKey = toBuffer(privateKey);
      if (!isValidPrivate(_privateKey)) {
        throw new Error(privateKey + " is not a valid private key");
      }
    } else {
      _privateKey = generatePrivateKey();
    }
    this._privateKey = _privateKey;
    this._publicKey = privateToPublic(this._privateKey);
    this._address = publicToAddress(this._publicKey);
    this.privateKey = bufferToHex(this._privateKey);
    this.publicKey = bufferToHex(this._publicKey);
    this.rawAddress = bufferToHex(this._address);
    this.address = toChecksumAddress(this.rawAddress);
  }

  getContractAddress(nonce) {
    const address = generateAddress(this._address, nonce);
    return bufferToHex(address);
  }

  generateWallet(password) {
    const privateKey = this._privateKey;
    const crypto = encryptPrivateKey(privateKey, password);
    return {
      crypto,
      id: v4(),
      version: 3
    };
  }
}
