package security;
/**
* This class implements Symetric Encryption
*
* @author  Rob
* @author  Sam
*/

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.example.hydrus.utilities.Base64Converter;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import functional.Maybe;

public class SymmetricEncryption {

    private static final String KEYSTORE = "AndroidKeyStore"; // TODO change to underscore
    private static final String SYMETRIC_KEY_ALIAS = "AndroidKeyStoreHydrusSymetricKeyTest11";
    private static final String _AES_ALGORITHM = "AES/CBC/PKCS7Padding";

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC STATIC
     -------------------------------------------------------------------------------------------------*/

    /**
    * Get symetric key with key ID
    *
    * @param keyID the ID of the symetric key
    * @return Maybe the signature
    */
    public static Maybe<SecretKey> maybeGetSymetricKeyWithID(String keyID) {
        try {
            return Maybe.asObject(_attemptToGetSymetricKeyWithKeyID(keyID));
        } catch (Exception e) {
            return Maybe.asNothing();
        }
    }

    /**
    * Create symetric key with keyID
    *
    * @param keyID the ID of the symetric key
    * @return whether key creation was successful
    */
    public static boolean initializeSymetricKeyWithKeyID(String keyID) {
        try {
            return _attemptToCreateSymetricKeyWithID(keyID);
        } catch (Exception e) {
            return false;
        }
    }

    /**
    * Maybe encrypt data with symetric key
    *
    * @param bytesToEncrypt the data to encrypt
    * @param keyID the ID of the symetric key
    * @return Maybe symetrically encrypted data 
    */
    public static Maybe<SymetricEncryptedData> maybeEncryptWithSecretKeyWithKeyID(byte[] bytesToEncrypt, String keyID) {
        try {
            return Maybe.asObject(_attemptToEncryptWithSecretKeyWithKeyID(bytesToEncrypt, keyID));
        } catch (Exception exception) {
            return Maybe.asNothing();
        }
    }

    /**
    * Maybe decrypt symetric encrypted data with symetric key
    *
    * @param symetricEncryptedData the data to decrypt
    * @param keyID the ID of the symetric key
    * @return Maybe decrypted data
    */
    public static Maybe<byte[]> maybeDecryptWithSecretKeyWithKeyID(SymetricEncryptedData symetricEncryptedData, String keyID) {
        try {
            return Maybe.asObject(_attemptToDecryptWithSecretKeyWithKeyID(symetricEncryptedData, keyID));
        }  catch (Exception exception) {
            return Maybe.asNothing();
        }
    }

    /*-------------------------------------------------------------------------------------------------
     * PRIVATE STATIC
     -------------------------------------------------------------------------------------------------*/
    private static boolean _attemptToCreateSymetricKeyWithID(String keyID) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        keyGenerator.init(
                new KeyGenParameterSpec.Builder(keyID,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setIsStrongBoxBacked(true)
                        //.setUserAuthenticationRequired(true)              // DEBUG TODO: Add back in
                        //.setUserAuthenticationValidityDurationSeconds(-1) // DEBUG TODO: ADD BACK IN
                        .build());
        SecretKey key = keyGenerator.generateKey();
        return true;
    }

    private static SecretKey _attemptToGetSymetricKeyWithKeyID(String keyID) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        return (SecretKey) keyStore.getKey(keyID, null);
    }

    private static SymetricEncryptedData _attemptToEncryptWithSecretKeyWithKeyID(byte[] bytesToEncrypt, String keyID) throws Exception {
        SecretKey symetricKey = getSymetricKeyWithID(keyID);
        Cipher cipher = Cipher.getInstance(_AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, symetricKey);
        String encryptedBytes = Base64Converter.encryptBASE64(cipher.doFinal(bytesToEncrypt));
        String ivString = Base64Converter.encryptBASE64(cipher.getIV());
        return SymetricEncryptedData.createSymetricEncryptedDataWithEncryptedDataAndIV(encryptedBytes, ivString);
    }

    private static byte[] _attemptToDecryptWithSecretKeyWithKeyID(SymetricEncryptedData symetricEncryptedData, String keyID) throws Exception {
        String ivString = symetricEncryptedData.getIV();
        String encryptedData = symetricEncryptedData.getEncryptedData();
        byte[] ivBytes = Base64Converter.decryptBASE64(ivString);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        byte[] bytesToDecrypt = Base64Converter.decryptBASE64(encryptedData);
        SecretKey symetricKey = getSymetricKeyWithID(keyID);
        Cipher cipher = Cipher.getInstance(_AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, symetricKey, ivSpec);
        return cipher.doFinal(bytesToDecrypt);
    }
}
