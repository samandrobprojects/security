package security;
/**
* This class implements Symetric Encryption with secure memory
*
* @author  Rob
* @author  Sam
*/

import javax.crypto.SecretKey;

import functional.Maybe;

public class SecureSymetricEncryption {

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC STATIC
     -------------------------------------------------------------------------------------------------*/

    /**
    * Get symetric key with key ID
    *
    * @param keyID the ID of the symetric key
    * @return Maybe the signature
    */
    public static Maybe<SecretKey> maybeGetSymetricKeyWithKeyID(String keyID) {
        return SymmetricEncryption.maybeGetSymetricKeyWithID(keyID);
    }

    /**
    * Create symetric key with keyID
    *
    * @param keyID the ID of the symetric key
    * @return whether key creation was successful
    */
    public static boolean initializeSymetricKeyWithKeyID(String keyID) {
        return SymmetricEncryption.initializeSymetricKeyWithKeyID(keyID);
    }

    /**
    * Maybe encrypt data with symetric key
    *
    * @param bytesToEncrypt the data to encrypt
    * @param keyID the ID of the symetric key
    * @return Maybe symetrically encrypted data 
    */
    public static Maybe<SymetricEncryptedData> encryptWithSecretKeyWithKeyID(SecureBytes bytesToEncrypt, String keyID) {
        Maybe<SymetricEncryptedData> maybeSymetricEncryptedData = SymmetricEncryption.maybeEncryptWithSecretKeyWithKeyID(bytesToEncrypt.getByteRepresentation(), keyID);
        bytesToEncrypt.securelyDeleteBytes();
        return maybeSymetricEncryptedData;
    }

    /**
    * Maybe decrypt symetric encrypted data with symetric key
    *
    * @param symetricEncryptedData the data to decrypt
    * @param keyID the ID of the symetric key
    * @return Maybe decrypted data
    */
    public static Maybe<SecureBytes> decryptWithSecretKeyWithKeyID(SymetricEncryptedData symetricEncryptedData, String keyID) {
        Maybe<byte[]> maybeDecryptedBytes = SymmetricEncryption.maybeDecryptWithSecretKeyWithKeyID(symetricEncryptedData, keyID);
        if(maybeDecryptedBytes.isNotNothing()) {
            SecureBytes decryptedBytesInSecureMemory = SecureBytes.secureBytesFromBytes(maybeDecryptedBytes.object());
            return Maybe.asObject(decryptedBytesInSecureMemory);
        } else {
            return Maybe.asNothing();
        }
    }
}
