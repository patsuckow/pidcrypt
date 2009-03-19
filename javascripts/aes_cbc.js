 /*----------------------------------------------------------------------------*/
 // Copyright (c) 2009 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*
*  AES CBC (Cipher Block Chaining) Mode for use in pidCrypt Library
*  The pidCrypt AES CBC mode is compatible with openssl aes-xxx-cbc mode
*  using the same algorithms for key and iv creation and padding as openssl.
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js), AES (aes_core.js)
*  and MD5 (md5.js)
*
/*----------------------------------------------------------------------------*/

if(typeof(pidCrypt) != 'undefined' &&
   typeof(pidCrypt.AES) != 'undefined' &&
   typeof(pidCrypt.MD5) != 'undefined')
{
  pidCrypt.AES.CBC = function () {
    this.env = new pidCrypt();
    this.aes = new pidCrypt.AES(this.env);
    this.getOutput = function(){
      return this.env.getOutput();
    }
    this.getAllMessages = function(lnbrk){
      return this.env.getAllMessages(lnbrk);
    }
  }
/**
 * Initialize CBC for encryption from password.
 * @param  password: String
 * @param  options {
 *           nBits: aes bit size (128, 192 or 256)
 *         }
*/
  pidCrypt.AES.CBC.prototype.init = function(password, options) {
    if(!options) options = {};
    var env = this.env;
    env.setDefaults();
    var pObj = this.env.getParams(); //loading defaults
    for(var o in options)
      pObj[o] = options[o];
    var k_iv = this.createKeyAndIv({password:password, salt: pObj.salt, bits: pObj.nBits});
    pObj.key = k_iv.key;
    pObj.iv = k_iv.iv;
    pObj.output = '';
    env.setParams(pObj)
    this.aes.init();
  }

/**
 * Initialize CBC for encryption from password.
 * @param  input: plain text
 * @param  password: String
 * @param  options {
 *           nBits: aes bit size (128, 192 or 256)
 *         }
*/
  pidCrypt.AES.CBC.prototype.initEncrypt = function(input, password, options) {
    this.init(password,options);//call standard init
    this.env.setParams({input:input})//setting input for encryption
  }
/**
 * Initialize CBC for decryption from encrypted text (compatible with openssl).
 * see thread http://thedotnet.com/nntp/300307/showpost.aspx
 * @param  crypted: base64 encoded aes encrypted text
 * @param  passwd: String
 * @param  options {
 *           nBits: aes bit size (128, 192 or 256),
 *           UTF8: boolean, set to false when decrypting certificates,
 *           A0_PAD: boolean, set to false when decrypting certificates
 *         }
*/
  pidCrypt.AES.CBC.prototype.initDecrypt = function(crypted, password, options){
    if(!options) options = {};
    var env = this.env;
    if(!password)
      env.appendError('pidCrypt.AES.CBC.initFromEncryption: Sorry, can not crypt or decrypt without password.\n');
    var cipherText = crypted.decodeBase64();
    if(cipherText.indexOf('Salted__') != 0)
      return env.appendError('pidCrypt.AES.CBC.initFromCrypt: Sorry, unknown encryption method.\n');
    var salt = cipherText.substr(8,8);//extract salt from crypted text
    options.salt = salt.convertToHex();//salt is always hex string
    this.init(password,options);//call standard init
    cipherText = cipherText.substr(16)
    env.setParams({input:cipherText.encodeBase64()})
  }
/**
 * Init CBC En-/Decryption from given parameters.
 * @param  input: plain text or base64 encrypted text
 * @param  key: HEX String (16, 24 or 32 byte)
 * @param  iv: HEX String (16 byte)
 * @param  options {
 *           salt: array of bytes (8 byte),
 *           nBits: aes bit size (128, 192 or 256)
 *         }
*/
  pidCrypt.AES.CBC.prototype.initByValues = function(input, key, iv, options){
    var pObj = {};
    this.init('',options);//empty password, we are setting key, iv manually
    pObj.input = input;
    pObj.key = key
    pObj.iv = iv
    this.env.setParams(pObj)
  }

  pidCrypt.AES.CBC.prototype.getAllMessages = function(lnbrk){
    return this.env.getAllMessages(lnbrk);
  }
/**
 * Creates key of length nBits and an iv form password+salt
 * compatible to openssl.
 * See thread http://thedotnet.com/nntp/300307/showpost.aspx
 *
 * @param  pObj {
 *    password: password as String
 *    [salt]: salt as String, default 8 byte random salt
 *    [bits]: no of bits, default pidCrypt.params.nBits = 256
 * }
 *
 * @return         {iv: HEX String, key: HEX String}
 */
  pidCrypt.AES.CBC.prototype.createKeyAndIv = function(pObj){
    var env = this.env;
    var retObj = {};
    var count = 1;//openssl rounds
    var miter = "3";
    if(!pObj) pObj = {};
    if(!pObj.salt) {
      pObj.salt = env.getRandomBytes(8);
      pObj.salt = byteArray2String(pObj.salt).convertToHex();
      env.setParams({salt: pObj.salt});
    }
    var data00 = pObj.password + pObj.salt.convertFromHex();
    var hashtarget = '';
    var result = '';
    var keymaterial = [];
    var loop = 0;
    keymaterial[loop++] = data00;
    for(var j=0; j<miter; j++){
      if(j == 0)
        result = data00;   	//initialize
      else {
        hashtarget = result.convertFromHex();
        hashtarget += data00;
        result = hashtarget;
      }
      for(var c=0; c<count; c++){
        result = pidCrypt.MD5(result);
      }
      keymaterial[loop++] = result;
    }
    switch(pObj.bits){
      case 128://128 bit
        retObj.key = keymaterial[1];
        retObj.iv = keymaterial[2];
        break;
      case 192://192 bit
        retObj.key = keymaterial[1] + keymaterial[2].substr(0,16);
        retObj.iv = keymaterial[3];
        break;
      case 256://256 bit
        retObj.key = keymaterial[1] + keymaterial[2];
        retObj.iv = keymaterial[3];
        break;
       default:
         env.appendError('pidCrypt.AES.CBC.createKeyAndIv: Sorry, only 128, 192 and 256 bits are supported.\nBits('+typeof(pObj.bits)+') = '+pObj.bits);
    }
    return retObj;
  }
/**
 * Encrypt a text using AES encryption in CBC mode of operation
 *  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 *
 * Unicode multi-byte character safe
 *
 * @return          encrypted text
 */
  pidCrypt.AES.CBC.prototype.encrypt = function(plaintext) {
    var env = this.env;
    var aes = this.aes;
    var salt = '';
    var p = env.getParams(); //get parameters for operation set by init
    var iv = p.iv.convertFromHex();
    plaintext = (!plaintext) ? p.input : plaintext;
    if(p.UTF8)
      plaintext = plaintext.encodeUTF8();
    //PKCS5 paddding
    var charDiv = p.blockSize - ((plaintext.length+1) % p.blockSize);
    if(p.A0_PAD)
      plaintext += String.fromCharCode(10)
    for(var c=0;c<charDiv;c++) plaintext += String.fromCharCode(charDiv);
    var nBytes = p.nBits/8;  // no bytes in key
    var keyBytes = new Array(nBytes);
    var key = p.key.convertFromHex();
    for (var i=0; i<nBytes; i++) {
      keyBytes[i] = isNaN(key.charCodeAt(i)) ? 0 : key.charCodeAt(i);
    }
    // generate key schedule
    var keySchedule = aes.expandKey(keyBytes);
    var blockCount = Math.ceil(plaintext.length/p.blockSize);
    var ciphertxt = new Array(blockCount);  // ciphertext as array of strings
    var textBlock = [];
    var state = iv.toByteArray();
    for (var b=0; b<blockCount; b++) {
      // XOR last block and next data block, then encrypt that
      textBlock = plaintext.substr(b*p.blockSize,p.blockSize).toByteArray();
      state = aes.xOr_Array(state, textBlock);
      state = aes.encrypt(state, keySchedule);  // -- encrypt block --
      ciphertxt[b] = byteArray2String(state);
    }
    var ciphertext = ciphertxt.join('');
    salt = 'Salted__' + p.salt.convertFromHex();
    ciphertext = salt  + ciphertext;
    ciphertext = ciphertext.encodeBase64();  // encode in base64
    //remove all parameters from enviroment for more security is debug off
    if(!env.isDebug() && env.clear) env.clearParams();
    env.setParams({output:ciphertext});

    return ciphertext;
  }
/**
 * Decrypt a text encrypted by AES in CBC mode of operation
 *
 * one of the pidCrypt.AES.CBC init funtions must be called before execution
 *
 * @return           decrypted text as String
 */
  pidCrypt.AES.CBC.prototype.decrypt = function(ciphertext) {
    var env = this.env;
    var aes = this.aes;
    var p = env.getParams(); //get parameters for operation set by init
    if((p.iv.length/2)<p.blockSize)
      return env.appendError('pidCrypt.AES.CBC.decrypt: Sorry, can not decrypt without complete set of parameters.\n Length of key,iv:'+p.key.length+','+p.iv.length);
    var iv = p.iv.convertFromHex();
    ciphertext = (!ciphertext) ? p.input : ciphertext;
    ciphertext = ciphertext.decodeBase64();
    if(ciphertext.length%p.blockSize != 0)
      return env.appendError('pidCrypt.AES.CBC.decrypt: Sorry, the encrypted text has the wrong length for aes-cbc mode\n Length of ciphertext:'+ciphertext.length+ciphertext.length%p.blockSize);
    if(ciphertext.indexOf('Salted__') == 0) ciphertext = ciphertext.substr(16);
    var nBytes = p.nBits/8;  // no bytes in key
    var keyBytes = new Array(nBytes);
    var key = p.key.convertFromHex();
    for (var i=0; i<nBytes; i++) {
      keyBytes[i] = isNaN(key.charCodeAt(i)) ? 0 : key.charCodeAt(i);
    }
    // generate key schedule
    var keySchedule = aes.expandKey(keyBytes);
    // separate ciphertext into blocks
    var nBlocks = Math.ceil((ciphertext.length) / p.blockSize);
    var ct = new Array(nBlocks);
    for (var b=0; b<nBlocks; b++) ct[b] = ciphertext.slice(b*p.blockSize, b*p.blockSize+p.blockSize);
    ciphertext = ct;  // ciphertext is now array of block-length strings
    // plaintext will get generated block-by-block into array of block-length strings
    var plaintxt = new Array(ciphertext.length);
    var state = iv.toByteArray();
    var ciphertextBlock = [];
    var dec_state = [];
    for (var b=0; b<nBlocks; b++) {
      ciphertextBlock = ciphertext[b].slice();
      dec_state = aes.decrypt(ciphertextBlock.toByteArray(), keySchedule);  // decrypt ciphertext block
      plaintxt[b] = byteArray2String(aes.xOr_Array(state, dec_state));
      state = ciphertextBlock.toByteArray(); //save old ciphertext for next round
    }
    // join array of blocks into single plaintext string
    var plaintext = plaintxt.join('');
    if(env.isDebug()) env.appendDebug('Padding after decryption:'+ plaintext.convertToHex() + ':' + plaintext.length + '\n');
    var endByte = plaintext.charCodeAt(plaintext.length-1);
    //remove oppenssl A0 padding eg. 0A05050505
    if(p.A0_PAD){
        plaintext = plaintext.substr(0,plaintext.length-(endByte+1));
    }
    else {
      var div = plaintext.length - (plaintext.length-endByte);
      var firstPadByte = plaintext.charCodeAt(plaintext.length-endByte);
      if(endByte == firstPadByte && endByte == div)
        plaintext = plaintext.substr(0,plaintext.length-endByte);
    }
    if(p.UTF8)
      plaintext = plaintext.decodeUTF8();  // decode from UTF8 back to Unicode multi-byte chars
    //remove all parameters from enviroment for more security is debug off
    if(!env.isDebug() && env.clear) env.clearParams();
    if(env.isDebug()) env.appendDebug('Removed Padding after decryption:'+ plaintext.convertToHex() + ':' + plaintext.length + '\n');
    env.setParams({output:plaintext});

    return plaintext;
  }
}

