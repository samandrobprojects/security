package security;
/**
* This class implements RSA 2048 Bit Aysmmetric Encryption For Secure Memory
*
* <p> Uses RSA 2048 Bit Encryption to encrypt, decrypt, sign, and veryify
* secure memory
*
* @author  Rob
* @author  Sam
*/

import com.example.hydrus.security.secure_memory.ConstantSecureMemory;
import com.example.hydrus.utilities.Base64Converter;
import com.example.hydrus.security.secure_memory.VariableSecureMemory;

import functional.Maybe;

public class SecureAsymmetricEncryption {

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC STATIC
     -------------------------------------------------------------------------------------------------*/

    /**
    * Create private-public keypair in keystore with alias
    *
    * @param keyID the keystore alias for the keypair
    * @return whether the keypair was initialized
    */
    public static boolean initializeKeyPairWithKeyID(String keyID) {
        return AsymmetricEncryption.initializeKeyPairWithKeyID(keyID);
    }

    /**
    * Get public key for keystore alias
    *
    * @param keyID the keystore keypair alias
    * @return Maybe the public key matching the given keystore alias
    */
    public static Maybe<SecureBytes> maybeGetPublicKeyWithKeyID(String keyID) {
        return SecureBytes.secureBytesFromBytes(AsymmetricEncryption.maybeGetPublicKeyWithKeyID(keyID));
    }

    /**
    * Encrypt data with private key
    *
    * @param secureBytesToEncrypt the data to encrypt
    * @param publicKey the public key to enrypt data with
    * @return Maybe the encrypted data
    */
    public static Maybe<String> maybeEncryptSecureByteDataWithPublicKeySecurelyErasingData(SecureBytes secureBytesToEncrypt, SecureBytes publicKey) {
        Maybe<String> maybeEncryptedData = AsymmetricEncryption.maybeEncryptByPublicKeyWithByteData(secureBytesToEncrypt.getByteRepresentation(), publicKey.getByteRepresentation());
        secureBytesToEncrypt.securelyDeleteBytes();
        return maybeEncryptedData;
    }

    /**
    * Decrypt data with private key
    *
    * @param stringData the data to decrypt
    * @param keyID the private key keystore alias
    * @return Maybe the decrypted data
    */
    public static Maybe<SecureBytes> maybeDecryptStringByPrivateKeyWithKeyID(String stringToDecrypt, String keyID) {
        Maybe<byte[]> maybeDecryptedBytes = AsymmetricEncryption.maybeDecryptByPrivateKeyWithKeyID(stringToDecrypt, keyID);
        if(maybeDecryptedBytes.isNotNothing()) {
            return Maybe.asObject(SecureBytes.secureBytesFromBytes(maybeDecryptedBytes.object()));
        } else {
            return Maybe.asNothing();
        }
    }

    /**
    * Sign given bytes with private key
    *
    * @param data the data to sign
    * @param keyID the private key keystore alias
    * @return Maybe the signature
    */
    public static Maybe<String> maybeSignBytesWithStoredPrivateKeyWithKeyID(byte[] bytesToSign, String keyID) {
        return AsymmetricEncryption.maybeSignBytesWithKeyID(bytesToSign, keyID);
    }

    /**
    * Sign string with private key
    *
    * @param stringData the data to sign
    * @param keyID the private key keystore alias
    * @return Maybe the signature
    */
    public static Maybe<String> maybeSignStringWithStoredPrivateKeyWithKeyID(String stringData, String keyID) {
        byte[] data = Base64Converter.decryptBASE64(stringData);
        return maybeSignBytesWithStoredPrivateKeyWithKeyID(data, keyID);
    }

    /**
    * Verify string data was signed with private-public keypair
    *
    * @param stringData the data to check matches signature
    * @param publicKey the public key from the private-public keypair that created the signature
    * @param sign the signature
    * @return Maybe the signature
    */
    public static boolean verifyStringWithPublicKeyAndSignature(String stringToVerify, SecureBytes publicKey, String signature) {
        byte[] bytesToVerify = Base64Converter.decryptBASE64(stringToVerify);
        return verifyBytesWithPublicKeyAndSignature(bytesToVerify, publicKey.getByteRepresentation(), signature);
    }

    /**
    * Verify data was signed with private-public keypair
    *
    * @param data the data to check matches signature
    * @param publicKey the public key from the private-public keypair that created the signature
    * @param sign the signature
    * @return Maybe the signature
    */
    public static boolean verifyBytesWithPublicKeyAndSignature(byte[] bytesToVerify, SecureBytes publicKey, String signature) {
        return AsymmetricEncryption.verifyBytes(bytesToVerify, publicKey.getByteRepresentation(), signature);
    }
}
