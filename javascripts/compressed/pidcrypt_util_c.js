/*Copyright (c) 2009 pidder <www.pidder.com>*/
/*(c) Chris Veness 2005-2008*/
String.prototype.encodeBase64=function(p){var h="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";p=(typeof p=="undefined")?false:p;var g,d,b,r,o,l,k,i,j=[],f="",n,q,m;var a=this.toByteArray();q=p?this.encodeUTF8():this;n=q.length%3;if(n>0){while(n++<3){f+="=";q+="\0"}}for(n=0;n<q.length;n+=3){g=q.charCodeAt(n);d=q.charCodeAt(n+1);b=q.charCodeAt(n+2);r=g<<16|d<<8|b;o=r>>18&63;l=r>>12&63;k=r>>6&63;i=r&63;j[n/3]=h.charAt(o)+h.charAt(l)+h.charAt(k)+h.charAt(i)}m=j.join("");m=m.slice(0,m.length-f.length)+f;return m};String.prototype.decodeBase64=function(f){var h="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";f=(typeof f=="undefined")?false:f;var g,e,b,o,l,j,i,q,k=[],p,n;n=f?this.decodeUTF8():this;for(var m=0;m<n.length;m+=4){o=h.indexOf(n.charAt(m));l=h.indexOf(n.charAt(m+1));j=h.indexOf(n.charAt(m+2));i=h.indexOf(n.charAt(m+3));q=o<<18|l<<12|j<<6|i;g=q>>>16&255;e=q>>>8&255;b=q&255;k[m/4]=String.fromCharCode(g,e,b);if(i==64){k[m/4]=String.fromCharCode(g,e)}if(j==64){k[m/4]=String.fromCharCode(g)}}p=k.join("");p=f?p.decodeUTF8():p;var a=p.toByteArray();return p};String.prototype.encodeUTF8=function(){var a=this.replace(/[\u0080-\u07ff]/g,function(d){var b=d.charCodeAt(0);return String.fromCharCode(192|b>>6,128|b&63)});a=a.replace(/[\u0800-\uffff]/g,function(d){var b=d.charCodeAt(0);return String.fromCharCode(224|b>>12,128|b>>6&63,128|b&63)});return a};String.prototype.decodeUTF8=function(){var a=this.replace(/[\u00c0-\u00df][\u0080-\u00bf]/g,function(d){var b=(d.charCodeAt(0)&31)<<6|d.charCodeAt(1)&63;return String.fromCharCode(b)});a=a.replace(/[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,function(d){var b=((d.charCodeAt(0)&15)<<12)|((d.charCodeAt(1)&63)<<6)|(d.charCodeAt(2)&63);return String.fromCharCode(b)});return a};String.prototype.convertToHex=function(){var c="";var a="";for(var b=0;b<this.length;b++){a=this.charCodeAt(b).toString(16);c+=(a.length==1)?"0"+a:a}return c};String.prototype.convertFromHex=function(){var b="";for(var a=0;a<this.length;a+=2){b+=String.fromCharCode(parseInt(this.substring(a,a+2),16))}return b};String.prototype.stripLineFeeds=function(){var a="";a=this.replace(/\n/g,"");a=a.replace(/\r/g,"");return a};String.prototype.toByteArray=function(){var b=[];for(var a=0;a<this.length;a++){b[a]=this.charCodeAt(a)}return b};String.prototype.fragment=function(d,a){if(!d||d>=this.length){return this}if(!a){a="\n"}var c="";for(var b=0;b<this.length;b+=d){c+=this.substr(b,d)+a}return c};String.prototype.formatHex=function(d){if(!d){d=45}var e="";var a=0;var c=this.toLowerCase();for(var b=0;b<c.length;b+=2){e+=c.substr(b,2)+":"}c=e.fragment(d);return c};function byteArray2String(a){var d="";for(var c=0;c<a.length;c++){d+=String.fromCharCode(a[c])}return d};