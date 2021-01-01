const crypto = require('crypto');

const AES_METHOD = 'aes-256-cbc';
const IV_LENGTH = 16; 


function encrypt(message, key_, hash_key) {
    let key = crypto.createHash('sha256').update(String(key_)).digest();

    let iv = crypto.randomBytes(IV_LENGTH)

    // let iv = '1234567890123456'

    const cipher = crypto.createCipheriv(AES_METHOD, key, iv);

    let ciphertext = cipher.update(message, 'utf8')

    ciphertext = Buffer.concat([ciphertext, cipher.final()])

    // return iv + ciphertext

    iv = Buffer.from(iv)

    let encrypted_data = Buffer.concat([iv, ciphertext])

    encrypted_data = encrypted_data.toString('base64')

    // return encrypted_data

    let encrypted_data_hash = crypto.createHmac('sha256', hash_key).update(encrypted_data).digest('hex')

    return encrypted_data_hash + encrypted_data
}

function decrypt(message, hash_key, key_){
    let hmac_input = crypto.createHmac('sha256', hash_key).update(message).digest('hex')
    let data = message.substring(hmac_input.length)
    data = Buffer.from(data, 'base64')

    let iv = Buffer.from(data).slice(0, IV_LENGTH)
    let ciphertext = Buffer.from(data).slice(IV_LENGTH)

    // return ciphertext
    let key = crypto.createHash('sha256').update(String(key_)).digest();
    
    let decipher = crypto.createDecipheriv(AES_METHOD, key, iv);
    let decrypted = decipher.update(ciphertext);

    // return decrypted

    decrypted = Buffer.concat([decrypted, decipher.final()]);

    // return decrypted

    return decrypted.toString('utf8')
}

const data = {
    key: 'key',
    hash_key: 'hash_key',
    message: 'message',
    encrypted_data: '0a3927cd0d0bf8d6ad716309a318853de168550088368b9530d07ec8dd8cee69MTIzNDU2Nzg5MDEyMzQ1NqmhR5n1oq9mMeTTvoPTMoc='
}

// console.log(encrypt(data.message, data.key, data.hash_key))

let encrypted_msg = encrypt(data.message, data.key, data.hash_key)

console.log(encrypted_msg, decrypt(encrypted_msg, data.hash_key, data.key))