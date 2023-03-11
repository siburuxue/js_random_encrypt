;
let CryptoJS = require('crypto-js');
let md5 = require('js-md5');
let RandomEncrypt = {
    tool: function (config) {
        this.timezone = -480;
        this.timeInterval = 5;
        this.keyLength = 16;
        this.secondRedundancy = 2;
        this.salt = "";
        this.timestamp = 0;
        this.map = {
            "1": '#',
            "2": '0',
            "3": '*',
            "4": '9',
            "5": '8',
            "6": '7',
            "7": '6',
            "8": '5',
            "9": '4',
            "*": '3',
            "0": '2',
            "#": '1',
        };
        // 获取当前时间戳
        this.getTimezoneTimestamp = function (timestamp = 0) {
            return Date.now();
        };
        this.getTimeGroup = function (time) {
            return Math.ceil(Math.floor(time / 1000) / this.timeInterval) * this.timeInterval * 1000;
        };
        // 加密
        this.encrypt = function (str) {
            let keyArr = this.key();
            // console.log("加密：key:", JSON.stringify(keyArr));
            let key = CryptoJS.enc.Utf8.parse(keyArr[0]);
            let iv = CryptoJS.enc.Utf8.parse(keyArr[1]);
            let encrypted = CryptoJS.AES.encrypt(str, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });
            return [encrypted.toString(), ...keyArr, this.timestamp];
        };
        this.decryptByKeyIv = function (str, key, iv) {
            key = CryptoJS.enc.Utf8.parse(key);
            iv = CryptoJS.enc.Utf8.parse(iv);
            let decrypted = CryptoJS.AES.decrypt(str, key, {iv: iv, padding: CryptoJS.pad.Pkcs7});
            return decrypted.toString(CryptoJS.enc.Utf8);
        };
        this.doDecrypt = function (str, timestamp) {
            // console.log("解密：timestamp: ", timestamp);
            let keyArr = this.key(timestamp);
            // console.log("解密：key:", JSON.stringify(keyArr));
            let key = CryptoJS.enc.Utf8.parse(keyArr[0]);
            let iv = CryptoJS.enc.Utf8.parse(keyArr[1]);
            try {
                let decrypted = CryptoJS.AES.decrypt(str, key, {iv: iv, padding: CryptoJS.pad.Pkcs7});
                return decrypted.toString(CryptoJS.enc.Utf8);
            } catch (e) {
                console.warn('字符串有问题')
                return "";
                // let decrypted = CryptoJS.AES.decrypt(JSON.stringify({str}), key, {iv: iv, padding: CryptoJS.pad.Pkcs7});
                // console.warn(decrypted);
                // return decrypted.toString(CryptoJS.enc.Utf8);
            }
        };
        this.isReDecrypt = function (timestamp) {
            return timestamp % this.timeInterval <= this.secondRedundancy
        };
        // 解密
        this.decrypt = function (str) {
            let current = this.getTimezoneTimestamp();
            let rs = this.doDecrypt(str, current);
            if (rs.trim().length === 0 && this.isReDecrypt(current)) {
                rs = this.doDecrypt(str, current - this.timeInterval * 1000);
            }
            return rs;
        };
        // 获取加/解密key
        this.key = function (timestamp = 0) {
            if (timestamp === 0) timestamp = this.getTimezoneTimestamp();
            this.timestamp = timestamp;
            // console.log(time / 1000)
            timestamp = this.getTimeGroup(timestamp);
            let datetime = this.formatDateTime(timestamp);
            // console.log(datetime)
            let key = datetime.split("").map(v => this.map[v]).join("");
            let index = parseInt(datetime) % this.keyLength;
            let passphrase = datetime + key + datetime;
            let iv = key + datetime + key;
            return [this.getEncryptKey(passphrase, index), this.getEncryptKey(iv, index)];
        };
        this.formatDateTime = function(timestamp){
            let date = new Date();
            let zone = date.getTimezoneOffset()
            let second = (zone - this.timezone) * 60 * 1000;
            timestamp += second;
            return this.CurrentTime("YmdHis", timestamp);
        };
        this.getEncryptKey = function (str, index) {
            if (this.salt === "") throw new Error("the salt can not be empty.");
            return md5(str + this.salt).substr(index, this.keyLength).toLowerCase();
        };
        /**
         * 获取当前日期 YYYYMMDDhis
         * @returns {string}
         */
        this.CurrentTime = function (format = 'YmdHis', timestamp = 0) {
            let now = null;
            if (timestamp > 0) {
                now = new Date(timestamp);
            } else {
                now = new Date();
            }
            let year = now.getFullYear();       //年
            let month = now.getMonth() + 1;     //月
            let day = now.getDate();            //日

            let h = now.getHours();            //时
            let i = now.getMinutes();          //分
            let s = now.getSeconds();          //秒

            if (month < 10) month = "0" + month;
            if (day < 10) day = "0" + day;
            if (h < 10) h = "0" + h;
            if (i < 10) i = '0' + i;
            if (s < 10) s = '0' + s;

            format = format.replace("Y", year.toString());
            format = format.replace("m", month.toString());
            format = format.replace("d", day.toString());
            format = format.replace("H", h.toString());
            format = format.replace("i", i.toString());
            format = format.replace("s", s.toString());

            return format;
        };
        /**
         * 自定义盐值 加密时不能为空
         * @param salt
         * @returns this
         */
        this.setSalt = function (salt) {
            this.salt = salt;
            return this;
        };
        /**
         * 自定义对齐时区 默认东八区 8
         * @return this
         * @param offset
         */
        this.setTimezoneOffset = function (offset) {
            this.timezone = (0 - parseInt(offset)) * 60;
            return this;
        };

        /**
         * 自定义加密key有效时间 默认5秒
         * key有效期为 timeInterval + secondRedundancy
         * @return this
         * @param timeInterval
         */
        this.setTimeInterval = function (timeInterval) {
            this.timeInterval = timeInterval;
            return this;
        };
        // 返回指定时区的时间
        this.getTimezoneDatetime = function (timestamp) {
            timestamp = this.getTimezoneTimestamp(timestamp * 1000);
            return this.CurrentTime("Y-m-d H:i:s", timestamp);
        };
        /**
         * 自定义跨区间 冗余秒数 默认2秒
         * key有效期为 timeInterval + secondRedundancy
         * @return this
         * @param secondRedundancy
         */
        this.setSecondRedundancy = function (secondRedundancy) {
            this.secondRedundancy = secondRedundancy;
            return this;
        };
        this.isSet = function(key){
            return typeof (config[key]) !== 'undefined';
        }
        if (this.isSet("salt")) {
            this.setSalt(config['salt']);
        }
        if (this.isSet("offset")) {
            this.setTimezoneOffset(parseInt(config['offset']));
        }
        if (this.isSet("timeInterval")) {
            this.setTimeInterval(parseInt(config['timeInterval']));
        }
        if (this.isSet("undefined")) {
            this.setSecondRedundancy(parseInt(config['secondRedundancy']));
        }
    },
    init: function (config) {
        return new this.tool(config);
    }
};

module.exports = RandomEncrypt;
