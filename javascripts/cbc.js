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
*  CBC (Cipher Block Chaining) Mode functions for use in pidCrypt Library
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js) and MD5 (md5.js)
*
/*----------------------------------------------------------------------------*/

if(typeof(pidCrypt) != 'undefined' &&
   typeof(pidCrypt.MD5) != 'undefined')
{
  pidCrypt.CBC = function (pidcrypt) {
    this.pidcrypt = (pidcrypt) ? pidcrypt : new pidCrypt();
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
  pidCrypt.CBC.prototype.createKeyAndIv = function(pObj){
    var pidcrypt = this.pidcrypt;
    var retObj = {};
    var count = 1;//openssl rounds
    var miter = "3";
    if(!pObj) pObj = {};
    if(!pObj.salt) {
      pObj.salt = pidcrypt.getRandomBytes(8);
      pObj.salt = pidcrypt.byteArray2String(pObj.salt).convertToHex();
      pidcrypt.setParams({salt: pObj.salt});
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
         pidcrypt.appendError('pidCrypt.CBC.createKeyAndIv: Sorry, only 128, 192 and 256 bits are supported.\nBits('+typeof(pObj.bits)+') = '+pObj.bits);
    }
    return retObj;
  }

}

