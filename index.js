"use strict"

/**
 * Generate Wechat signature for JS-SDK
 *
 * NOTE: Please cache the Ticket for 7200 seconds
 * 
 * @author Enda Xue <xueenda@gmail.com>
 *
 */

/**
 * Module dependencies.
 */

var https = require("https");
var jsSHA = require('jssha');

var WECHAT_TICKET_URI = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket';
var WECHAT_TOKEN_URI = 'https://api.weixin.qq.com/cgi-bin/token';

// Save accessToken in memeory for 7200 seconds
var accessToken = null;

/**
 * Initialize the WechatSignTicket class
 * 
 * @param {string} appid
 * @param {string} secret
 */
function WechatSignTicket(appid, secret){
  if (!(this instanceof WechatSignTicket)) {
    return new WechatSignTicket(appid, secret);
  }
  this.appid = appid;
  this.secret = secret;
}

WechatSignTicket.prototype = {

	get: function(url, callback){
		var url = url.toLowerCase();
		if(!url){
			return callback(new Error('No url given'));
		}

		if(accessToken && accessToken.expire >= getTimeStamp()){
			return getTicket(url, accessToken.value, callback);
		}else{
			console.log('No access_token');

			var get_token_url = WECHAT_TOKEN_URI  + '?grant_type=client_credential&appid='+ this.appid +'&secret=' + this.secret;

			https.get(get_token_url, function(_res) {
				var str = '';
				_res.on('data', function(data){
					str += data;
				});
				_res.on('end', function(){
					try{
						var resp = JSON.parse(str);
					}catch(e){
				        return callback(new Error('Can\'t get access_token from JSON parser'));
					}
					if(resp.errcode)
						callback(new Error('Get wechat token: '+resp.errmsg));
					accessToken = {
						value: resp.access_token,
						expire: getTimeStamp(7200)
					}
					return getTicket(url, resp.access_token, callback);
				});
			});
		}
	}
};

// 随机字符串产生函数
var createNonceStr = function() {
	return Math.random().toString(36).substr(2, 15);
};

// 时间戳产生函数
var getTimeStamp = function (seconds) {
	seconds = seconds || 0;
	return parseInt(new Date().getTime() / 1000) + seconds + '';
};

// 计算签名
var calcSignature = function (ticket, noncestr, ts, url) {
	var str = 'jsapi_ticket=' + ticket + '&noncestr=' + noncestr + '&timestamp='+ ts +'&url=' + url;
	var shaObj = new jsSHA(str, 'TEXT');
	return shaObj.getHash('SHA-1', 'HEX');
};

// 获取微信签名所需的ticket
var getTicket = function (url, access_token, callback) {
	https.get(WECHAT_TICKET_URI + '?access_token='+ access_token +'&type=jsapi', function(_res){
		var str = '', resp;
		_res.on('data', function(data){
			str += data;
		});
		_res.on('end', function(){
			console.log('return ticket:  ' + str);
			try{
				resp = JSON.parse(str);
			}catch(e){
		        return callback(new Error('解析远程JSON数据错误'));
			}

			var ts = getTimeStamp();
			var nonceStr = createNonceStr();
			var ticket = resp.ticket;
			var signature = calcSignature(ticket, nonceStr, ts, url);

			var ticketData = {
				url: url,
				nonceStr: nonceStr,
				signature: signature,
				timestamp: ts
			};

			callback(null, ticketData);
		});
	});
};

module.exports = WechatSignTicket;