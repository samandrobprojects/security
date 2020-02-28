package security;
/**
* This class represents data encrypted using symetric encryption
*
* @author  Rob
* @author  Sam
*/

public class SymetricEncryptedData {

    private final String _encryptedData;
    private final String _iv;

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC STATIC
     -------------------------------------------------------------------------------------------------*/

    /**
    * Constructor
    *
    * @param encryptedData the encrypted data
    * @param iv the iv for the encrypted data
    * @return new SymetricEncryptedData instance
    */
    SymetricEncryptedData(String encryptedData, String iv) {
        _encryptedData = encryptedData;
        _iv = iv;
    }

    /**
    * Static Constructor
    *
    * @param encryptedData the encrypted data
    * @param iv the iv for the encrypted data
    * @return new SymetricEncryptedData instance
    */
    public static SymetricEncryptedData createSymetricEncryptedDataWithEncryptedDataAndIV(String encryptedData, String iv) {
        return new SymetricEncryptedData(encryptedData, iv);
    }

    /**
    * Get the encrypted data
    *
    * @return the encrypted data
    */
    public String getEncryptedData() {
        return _encryptedData;
    }

    /**
    * Get the IV for this symetric encrypted data
    *
    * @return the IV for this symetric encrypted data
    */
    public String getIV() {
        return _iv;
    }
}
