/*Copyright (c) 2009 pidder <www.pidder.com>*/
if(typeof(pidCrypt)!="undefined"&&typeof(pidCrypt.AES)!="undefined"&&typeof(pidCrypt.MD5)!="undefined"){pidCrypt.AES.CBC=function(){this.pidcrypt=new pidCrypt();this.aes=new pidCrypt.AES(this.pidcrypt);this.getOutput=function(){return this.pidcrypt.getOutput()};this.getAllMessages=function(a){return this.pidcrypt.getAllMessages(a)};this.isError=function(){return this.pidcrypt.isError()}};pidCrypt.AES.CBC.prototype.init=function(b,a){if(!a){a={}}var f=this.pidcrypt;f.setDefaults();var e=this.pidcrypt.getParams();for(var d in a){e[d]=a[d]}var c=this.createKeyAndIv({password:b,salt:e.salt,bits:e.nBits});e.key=c.key;e.iv=c.iv;e.dataOut="";f.setParams(e);this.aes.init()};pidCrypt.AES.CBC.prototype.initEncrypt=function(c,b,a){this.init(b,a);this.pidcrypt.setParams({dataIn:c,encryptIn:c.toByteArray()})};pidCrypt.AES.CBC.prototype.initDecrypt=function(e,b,a){if(!a){a={}}var f=this.pidcrypt;f.setParams({dataIn:e});if(!b){f.appendError("pidCrypt.AES.CBC.initFromEncryption: Sorry, can not crypt or decrypt without password.\n")}var d=e.decodeBase64();if(d.indexOf("Salted__")!=0){f.appendError("pidCrypt.AES.CBC.initFromCrypt: Sorry, unknown encryption method.\n")}var c=d.substr(8,8);a.salt=c.convertToHex();this.init(b,a);d=d.substr(16);f.setParams({decryptIn:d.toByteArray()})};pidCrypt.AES.CBC.prototype.initByValues=function(c,d,b,a){var e={};this.init("",a);e.dataIn=c;e.key=d;e.iv=b;this.pidcrypt.setParams(e)};pidCrypt.AES.CBC.prototype.getAllMessages=function(a){return this.pidcrypt.getAllMessages(a)};pidCrypt.AES.CBC.prototype.createKeyAndIv=function(b){var i=this.pidcrypt;var h={};var l=1;var d="3";if(!b){b={}}if(!b.salt){b.salt=i.getRandomBytes(8);b.salt=byteArray2String(b.salt).convertToHex();i.setParams({salt:b.salt})}var e=b.password+b.salt.convertFromHex();var a="";var n="";var f=[];var k=0;f[k++]=e;for(var g=0;g<d;g++){if(g==0){n=e}else{a=n.convertFromHex();a+=e;n=a}for(var m=0;m<l;m++){n=pidCrypt.MD5(n)}f[k++]=n}switch(b.bits){case 128:h.key=f[1];h.iv=f[2];break;case 192:h.key=f[1]+f[2].substr(0,16);h.iv=f[3];break;case 256:h.key=f[1]+f[2];h.iv=f[3];break;default:i.appendError("pidCrypt.AES.CBC.createKeyAndIv: Sorry, only 128, 192 and 256 bits are supported.\nBits("+typeof(b.bits)+") = "+b.bits)}return h};pidCrypt.AES.CBC.prototype.encryptRaw=function(h){var a=this.pidcrypt;var k=this.aes;var l=a.getParams();if(!h){h=l.encryptIn}a.setParams({encryptIn:h});if(!l.dataIn){a.setParams({dataIn:h})}var d=l.iv.convertFromHex();var j=l.blockSize-((h.length+1)%l.blockSize);if(l.A0_PAD){h[h.length]=10}for(var r=0;r<j;r++){h[h.length]=j}var f=Math.floor(l.nBits/8);var m=new Array(f);var v=l.key.convertFromHex();for(var o=0;o<f;o++){m[o]=isNaN(v.charCodeAt(o))?0:v.charCodeAt(o)}var s=k.expandKey(m);var n=Math.ceil(h.length/l.blockSize);var g=new Array(n);var q=[];var e=d.toByteArray();for(var t=0;t<n;t++){q=h.slice(t*l.blockSize,t*l.blockSize+l.blockSize);e=k.xOr_Array(e,q);e=k.encrypt(e.slice(),s);g[t]=byteArray2String(e)}var u=g.join("");a.setParams({dataOut:u,encryptOut:u});if(!a.isDebug()&&a.clear){a.clearParams()}return u||""};pidCrypt.AES.CBC.prototype.encrypt=function(c){var e=this.pidcrypt;var a="";var d=e.getParams();if(!c){c=d.dataIn}if(d.UTF8){c=c.encodeUTF8()}e.setParams({dataIn:c,encryptIn:c.toByteArray()});var b=this.encryptRaw();a="Salted__"+d.salt.convertFromHex();b=a+b;b=b.encodeBase64();e.setParams({dataOut:b});if(!e.isDebug()&&e.clear){e.clearParams()}return b||""};pidCrypt.AES.CBC.prototype.encryptText=function(c,b,a){this.initEncrypt(c,b,a);return this.encrypt()};pidCrypt.AES.CBC.prototype.decryptRaw=function(k){var n=this.aes;var c=this.pidcrypt;var o=c.getParams();if(!k){k=o.decryptIn}c.setParams({decryptIn:k});if(!o.dataIn){c.setParams({dataIn:k})}if((o.iv.length/2)<o.blockSize){return c.appendError("pidCrypt.AES.CBC.decrypt: Sorry, can not decrypt without complete set of parameters.\n Length of key,iv:"+o.key.length+","+o.iv.length)}var f=o.iv.convertFromHex();if(k.length%o.blockSize!=0){return c.appendError("pidCrypt.AES.CBC.decrypt: Sorry, the encrypted text has the wrong length for aes-cbc mode\n Length of ciphertext:"+k.length+k.length%o.blockSize)}var j=Math.floor(o.nBits/8);var q=new Array(j);var w=o.key.convertFromHex();for(var s=0;s<j;s++){q[s]=isNaN(w.charCodeAt(s))?0:w.charCodeAt(s)}var t=n.expandKey(q);var e=Math.ceil((k.length)/o.blockSize);var a=new Array(e.length);var g=f.toByteArray();var d=[];var v=[];for(var u=0;u<e;u++){d=k.slice(u*o.blockSize,u*o.blockSize+o.blockSize);v=n.decrypt(d,t);a[u]=byteArray2String(n.xOr_Array(g,v));g=d.slice()}var h=a.join("");if(c.isDebug()){c.appendDebug("Padding after decryption:"+h.convertToHex()+":"+h.length+"\n")}var r=h.charCodeAt(h.length-1);if(o.A0_PAD){h=h.substr(0,h.length-(r+1))}else{var l=h.length-(h.length-r);var m=h.charCodeAt(h.length-r);if(r==m&&r==l){h=h.substr(0,h.length-r)}}c.setParams({dataOut:h,decryptOut:h});if(!c.isDebug()&&c.clear){c.clearParams()}return h||""};pidCrypt.AES.CBC.prototype.decrypt=function(c){var e=this.pidcrypt;var d=e.getParams();if(c){e.setParams({dataIn:c})}if(!d.decryptIn){var a=d.dataIn.decodeBase64();if(a.indexOf("Salted__")==0){a=a.substr(16)}e.setParams({decryptIn:a.toByteArray()})}var b=this.decryptRaw();if(d.UTF8){b=b.decodeUTF8()}if(e.isDebug()){e.appendDebug("Removed Padding after decryption:"+b.convertToHex()+":"+b.length+"\n")}e.setParams({dataOut:b});if(!e.isDebug()&&e.clear){e.clearParams()}return b||""};pidCrypt.AES.CBC.prototype.decryptText=function(c,b,a){this.initDecrypt(c,b,a);return this.decrypt()}};