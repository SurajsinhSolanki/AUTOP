class TOTP {
    static generate(key, options = {}) {
        const {
            digits = 6,
            algorithm = 'sha1',
            period = 30,
            timestamp = Date.now(),
        } = options;

        const epoch = Math.floor(timestamp / 1000);
        const timeHex = this.leftpad(
            this.dec2hex(Math.floor(epoch / period)),
            16,
            '0'
        );

        // Convert timeHex to a WordArray for CryptoJS
        const timeBytes = CryptoJS.enc.Hex.parse(timeHex);
        // Convert base32 key to a WordArray
        const keyBytes = CryptoJS.enc.Hex.parse(this.base32tohex(key));
        
        // Create HMAC using CryptoJS
        const hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo[algorithm.toUpperCase()], keyBytes);
        hmac.update(timeBytes);
        const hmacResult = hmac.finalize();
        
        // Convert HMAC result to hex
        const hmacHex = hmacResult.toString(CryptoJS.enc.Hex);

        // Extract OTP
        const offset = parseInt(hmacHex.slice(-1), 16);
        const otp = (
            parseInt(
                hmacHex.substr(offset * 2, 8),
                16
            ) & 0x7fffffff
        )
            .toString()
            .slice(-digits);

        const expires =
            Math.ceil((timestamp + 1) / (period * 1000)) * period * 1000;
        return { otp, expires };
    }

    static leftpad(str, length, pad) {
        return str.padStart(length, pad);
    }

    static dec2hex(dec) {
        return dec.toString(16);
    }

    static base32tohex(base32) {
        const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        let hex = '';

        for (const char of base32.replace(/=+$/, '')) {
            const val = base32chars.indexOf(char.toUpperCase());
            bits += val.toString(2).padStart(5, '0');
        }

        for (let i = 0; i + 4 <= bits.length; i += 4) {
            hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
        }

        return hex;
    }
}

// Event listener for the form submission
document
    .getElementById('otp-form')
    .addEventListener('submit', function (event) {
        event.preventDefault();

        const secret = document.getElementById('secret').value;
        const otpData = TOTP.generate(secret);
        document.getElementById('otp-result').innerText = `OTP: ${
            otpData.otp
        }, Expires: ${new Date(otpData.expires).toLocaleTimeString()}`;
    });
