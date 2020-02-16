const crypto = require('crypto');

function pbkdf2(passphrase, salt) {
    return crypto.pbkdf2Sync(
        passphrase,
        salt,
        100000,
        32,
        'sha512'
    );
}

function sha512(mac_address, passphrase) {
    const salt = "7a1c4b0231f54bc8d11a773c1ced970811ba4fdcea3f968cd5c1c5e36797c3db";
    const hash = crypto.createHash("sha512");
    hash.update(Buffer.from(salt, 'hex'));
    hash.update(mac_address);
    hash.update(passphrase);
    const result = hash.digest();
    return result.toString('hex');
}

function decipher(passphrase, device) {
    const key = pbkdf2(passphrase, Buffer.from(device.kdf_salt, 'hex'));
    const algorithm = 'aes-256-ctr';
    const iv = Buffer.from(device.aes_ctr_nonce, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    let decrypted = decipher.update(device.ciphertext, 'hex', 'utf8')
    decrypted += decipher.final();
    return decrypted;
}

global.sha512 = sha512;
global.decipher = decipher;