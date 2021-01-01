<?php namespace projects\Custom;
class Encryption
{

    const METHOD = 'AES-256-CBC';
    private $__key; //where the key will be stored
    private $__hashkey; //where the key will be stored

    /**
     * This function implements the algorithm outlined
     * @param string $key    the string to use for the opensslkey
     * @param  string $hashkey the string is used for the hash_mac key
     * @return string
     */
    public function __construct(string $key, string $hashkey)
    {
        //convert the string into a binary
        $key = hash('SHA256', $key, true);
        if (!extension_loaded('openssl')) {
            //check if open ssl is loaded]
            throw new \Exception("openssl isnt loaded");
        }
        if (mb_strlen($key, '8bit') !== 32) {
            throw new \Exception("Needs a 256-bit key!");
        }
        if ($hashkey === "") {
            throw new \Exception("Hash Key needs to be set");
        }
        $this->__key     = $key; //initialize the key
        $this->__hashkey = $hashkey; //initialize the key
    }

    /**
     * This function implements the algorithm outlined
     * @param string $message    the string to  be encrypted
     * @return string as an encrypted value and added hash to it
     */
    public function encrypt(string $message): string
    {

        $ivsize = openssl_cipher_iv_length(self::METHOD);
        // $iv = openssl_random_pseudo_bytes($ivsize);
        $iv = '1234567890123456';

        $ciphertext = openssl_encrypt($message, self::METHOD, $this->__key, OPENSSL_RAW_DATA, $iv);
        // die(utf8_encode($iv . $ciphertext));
        $encrypted_data = base64_encode($iv . $ciphertext);
        // die($encrypted_data);
        //add a MAC to this function
        $encrypted_data_hash = hash_hmac("sha256", $encrypted_data, $this->__hashkey);
        // die($encrypted_data_hash);
        return $encrypted_data_hash . $encrypted_data;

    } //end of encrypt function

    /**
     * This function implements the algorithm outlined
     * @param string $message    the string to  be encrypted
     * @return string as an decrypted value and added hash to it
     */
    public function decrypt(string $message): string
    {
        //get the hash input
        // $hmac_input = substr($message, 0, 64); //the value will be 64 coz of the algorithm used
        $hmac_input = hash_hmac("sha256", $message, $this->__hashkey);
        // var_dump(strlen($hmac_input)); die();
        $data = substr($message, strlen($hmac_input));
        // die($data);
        // $generated_hash = hash_hmac("sha256", $data, $this->__hashkey);
        // if($generated_hash != $hmac_input)://throw an exception
        //  throw new Exception("Hash Does Not Match");
        // endif;
        $data = base64_decode($data, true);
        // die($data);

        $ivsize = openssl_cipher_iv_length(self::METHOD);
        $iv = mb_substr($data, 0, $ivsize, '8bit');
        $ciphertext = mb_substr($data, $ivsize, null, '8bit');
        // die($ciphertext);
        die($this->__key);
        $decrypted_data = openssl_decrypt($ciphertext, self::METHOD, $this->__key, OPENSSL_RAW_DATA, $iv);

        return $decrypted_data;

    } //end of decrypting function
}
$encrypted_msg = '0a3927cd0d0bf8d6ad716309a318853de168550088368b9530d07ec8dd8cee69MTIzNDU2Nzg5MDEyMzQ1NqmhR5n1oq9mMeTTvoPTMoc=';
$encrypt = new Encryption('key', 'hash_key');
// $encrypted_msg = $encrypt->encrypt('message');
// echo $encrypted_msg;
echo $encrypt->decrypt($encrypted_msg);