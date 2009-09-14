/*!Copyright (c) 2009 pidder <www.pidder.com>*/
/*----------------------------------------------------------------------------*/
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
*  Twofish CBC (Cipher Block Chaining) Mode for use in pidCrypt Library
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js) and MD5 (md5.js)
*
/*----------------------------------------------------------------------------*/

if(typeof(pidCrypt) != 'undefined' &&
   typeof(pidCrypt.Twofish) != 'undefined' &&
   typeof(pidCrypt.CBC) != 'undefined' &&
   typeof(pidCrypt.MD5) != 'undefined')
{
  pidCrypt.Twofish.CBC = function () {
    this.pidcrypt = new pidCrypt();
    this.twofish = new pidCrypt.Twofish(this.pidcrypt);
    this.cbc = new pidCrypt.CBC(this.pidcrypt);

    //shortcuts to pidcrypt methods
    this.getOutput = function(){
      return this.pidcrypt.getOutput();
    }
    this.getAllMessages = function(lnbrk){
      return this.pidcrypt.getAllMessages(lnbrk);
    }
    this.isError = function(){
      return this.pidcrypt.isError();
    }
  }

  pidCrypt.Twofish.CBC.prototype.init = function(password, options) {
    if(!options) options = {};
    var pidcrypt = this.pidcrypt;
    pidcrypt.setDefaults();
    var pObj = this.pidcrypt.getParams(); //loading defaults
    for(var o in options)
      pObj[o] = options[o];
    var k_iv = this.cbc.createKeyAndIv({password:password, salt: pObj.salt, bits: pObj.nBits});
    pObj.key = k_iv.key;
    pObj.iv = k_iv.iv;
    pObj.dataOut = '';
    pidcrypt.setParams(pObj)
  }

  pidCrypt.Twofish.CBC.prototype.initByValues = function(dataIn, key, iv, options){
    var pObj = {};
    this.init('',options);//empty password, we are setting key, iv manually
    pObj.dataIn = dataIn;
    pObj.key = key;
    pObj.iv = iv;
    this.pidcrypt.setParams(pObj)
  }



  pidCrypt.Twofish.CBC.prototype.encryptRaw = function(byteArray)
  {
    var pidcrypt = this.pidcrypt;
    var twofish = this.twofish;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!byteArray)
      byteArray = p.encryptIn;
    pidcrypt.setParams({encryptIn: byteArray});
    if(!p.dataIn) pidcrypt.setParams({dataIn:byteArray});
    var iv = p.iv.convertFromHex();
    //PKCS5 paddding
    if(!p.noPadding)
    {
      var charDiv = p.blockSize - ((byteArray.length+1) % p.blockSize);
      if(p.A0_PAD)
        byteArray[byteArray.length] = 10
      for(var c=0;c<charDiv;c++) byteArray[byteArray.length] = charDiv;
    }
    var nBytes = Math.floor(p.nBits/8);  // nr of bytes in key
    var keyBytes = new Array(nBytes);
    var key = p.key.convertFromHex();
    for (var i=0; i<nBytes; i++) {
      keyBytes[i] = isNaN(key.charCodeAt(i)) ? 0 : key.charCodeAt(i);
    }
    // generate keys
    twofish.init(keyBytes);
    var blockCount = Math.ceil(byteArray.length/p.blockSize);
    var ciphertxt = new Array(blockCount);  // ciphertext as array of strings
    var textBlock = [];
    var state = iv.toByteArray();
    for (var b=0; b<blockCount; b++) {
      // XOR last block and next data block, then encrypt that
      textBlock = byteArray.slice(b*p.blockSize, b*p.blockSize+p.blockSize);
      state = pidcrypt.xOr_Array(state.slice(), textBlock.slice());
//      alert(state +'='+twofish.encrypt(state.slice()));
      state = twofish.encrypt(state.slice());  // -- encrypt block --
      ciphertxt[b] = pidcrypt.byteArray2String(state);
    }
    var ciphertext = ciphertxt.join('');
    pidcrypt.setParams({dataOut:ciphertext, encryptOut:ciphertext});

    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();
   return ciphertext || '';
  }

 pidCrypt.Twofish.CBC.prototype.encrypt = function(plaintext) {
    var pidcrypt = this.pidcrypt;
    var salt = '';
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!plaintext)
      plaintext = p.dataIn;
    if(p.UTF8)
      plaintext = plaintext.encodeUTF8();
    pidcrypt.setParams({dataIn:plaintext, encryptIn: plaintext.toByteArray()});
    var ciphertext = this.encryptRaw()
    salt = 'Salted__' + p.salt.convertFromHex();
    ciphertext = salt  + ciphertext;
    ciphertext = ciphertext.encodeBase64();  // encode in base64
    pidcrypt.setParams({dataOut:ciphertext});
    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();

    return ciphertext || '';
  }


  pidCrypt.Twofish.CBC.prototype.decryptRaw = function(byteArray)
  {
    var twofish = this.twofish;
    var pidcrypt = this.pidcrypt;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!byteArray)
      byteArray = p.decryptIn;
    pidcrypt.setParams({decryptIn: byteArray});
    if(!p.dataIn) pidcrypt.setParams({dataIn:byteArray});
    if((p.iv.length/2)<p.blockSize)
      return pidcrypt.appendError('pidCrypt.Twofish.CBC.decrypt: Sorry, can not decrypt without complete set of parameters.\n Length of key,iv:'+p.key.length+','+p.iv.length);
    var iv = p.iv.convertFromHex();
    if(byteArray.length%p.blockSize != 0)
      return pidcrypt.appendError('pidCrypt.Twofish.CBC.decrypt: Sorry, the encrypted text has the wrong length for aes-cbc mode\n Length of ciphertext:'+byteArray.length+byteArray.length%p.blockSize);
    var nBytes = Math.floor(p.nBits/8);  // nr of bytes in key
    var keyBytes = new Array(nBytes);
    var key = p.key.convertFromHex();
    for (var i=0; i<nBytes; i++) {
      keyBytes[i] = isNaN(key.charCodeAt(i)) ? 0 : key.charCodeAt(i);
    }
    // generate keys
    twofish.init(keyBytes);
    // separate byteArray into blocks
    var nBlocks = Math.ceil((byteArray.length) / p.blockSize);
    // plaintext will get generated block-by-block into array of block-length strings
    var plaintxt = new Array(nBlocks.length);
    var state = iv.toByteArray();
    var ciphertextBlock = [];
    var dec_state = [];
    for (var b=0; b<nBlocks; b++) {
      ciphertextBlock = byteArray.slice(b*p.blockSize, b*p.blockSize+p.blockSize);
      dec_state = twofish.decrypt(ciphertextBlock.slice());  // decrypt ciphertext block
      plaintxt[b] = pidcrypt.byteArray2String(pidcrypt.xOr_Array(state, dec_state));
      state = ciphertextBlock.slice(); //save old ciphertext for next round
//      alert(plaintxt[b]+':'+pidcrypt.byteArray2String(ciphertextBlock));
    }

    // join array of blocks into single plaintext string and return it
    var plaintext = plaintxt.join('');
    if(pidcrypt.isDebug()) pidcrypt.appendDebug('Padding after decryption:'+ plaintext.convertToHex() + ':' + plaintext.length + '\n');
    var bArray = plaintext.toByteArray();
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
    pidcrypt.setParams({dataOut: plaintext,decryptOut: plaintext});

    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();

   return plaintext || '';

  }


  pidCrypt.Twofish.CBC.prototype.decrypt = function(ciphertext) {
    var pidcrypt = this.pidcrypt;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(ciphertext)
      pidcrypt.setParams({dataIn:ciphertext});
    if(!p.decryptIn) {
      var decryptIn = p.dataIn.decodeBase64();
      if(decryptIn.indexOf('Salted__') == 0) decryptIn = decryptIn.substr(16);
      pidcrypt.setParams({decryptIn: decryptIn.toByteArray()});
    }
    var plaintext = this.decryptRaw();
    if(p.UTF8)
      plaintext = plaintext.decodeUTF8();  // decode from UTF8 back to Unicode multi-byte chars
    if(pidcrypt.isDebug()) pidcrypt.appendDebug('Removed Padding after decryption:'+ plaintext.convertToHex() + ':' + plaintext.length + '\n');
    pidcrypt.setParams({dataOut:plaintext});

    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();
    return plaintext || '';
  }

}

