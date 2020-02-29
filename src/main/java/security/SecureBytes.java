package security;
/**
* This class represents secyre byte memory, that can be erased
*
* <p> This class is basically adds the ability to a byte array, which
* is the ability to securely delete memory
*
* @author  Rob
* @author  Sam
*/

public class SecureBytes {

    private byte[] _bytes;

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC
     -------------------------------------------------------------------------------------------------*/

    /**
    * Check if two objects are equal
    *
    * @param objectToCompareTo the object to compare this instance too
    * @return whether both instances share the same memory values
    */
    @Override
    public boolean equals(Object objectToCompareTo) {
        if (objectToCompareTo == null || getClass() != objectToCompareTo.getClass()) {
            return false;
        }
        return _compareMemoryToMemoryIn((SecureBytes) objectToCompareTo);
    }

    /**
    * Erase bytes in this secure byte instance
    */
    public void securelyEraseBytes() {
        SecureEraser.eraseByteArray(this._bytes);
        _bytes = new byte[0];
    }

    /**
    * Get the number of bytes in this secure byte instance
    *
    * @return number of bytes in this secure byte instance
    */
    public int getLength() {
        return _bytes.length;
    }

    /**
    * Return secure byte instance as a byte array
    *
    * @return the byte array containing secure byte instance memory
    */
    public byte[] getByteRepresentation() {
        return _bytes;
    }

    /**
    * Append given bytes to secure bytes
    *
    * @param bytesToAppend the byte array to append into secure byte instance
    */
    public void appendBytes(byte[] bytesToAppend) {
        byte[] newBytes = new byte[_bytes.length + bytesToAppend.length];
        _securelyCopyBytesFromIndexIntoBytesFromIndexWithLength(_bytes, 0, newBytes, 0, _bytes.length);
        _securelyCopyBytesFromIndexIntoBytesFromIndexWithLength(bytesToAppend, 0, newBytes, _bytes.length, bytesToAppend.length);
        _bytes = newBytes;
    }

    /**
    * Remove a byte from the secure byte instance
    */
    public void removeByte() {
        if(_bytes.length > 0) {
            byte[] newBytes = new byte[_bytes.length - 1];
            _securelyCopyBytesFromIndexIntoBytesFromIndexWithLength(_bytes, 0, newBytes, 0, _bytes.length - 1);
            _bytes = newBytes;   
        }
    }

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC STATIC
     -------------------------------------------------------------------------------------------------*/
    
    /**
    * Constructor for SecureBytes with given bytes
    *
    * @param bytes the bytes to inject into the secure bytes instance
    * @return SecureByte instance
    */
    public static SecureBytes secureBytesFromBytes(byte[] bytes) {
        SecureBytes secureBytes = new SecureBytes();
        secureBytes.appendBytes(bytes);
        SecureEraser.eraseByteArray(bytes);
        return secureBytes;
    }

    /**
    * Constructor for SecureBytes which is empty
    *
    * @return SecureByte instance
    */
    public static SecureBytes emptySecureBytes() {
        SecureBytes emptySecureBytes = new SecureBytes();
        return emptySecureBytes;
    }

    /*-------------------------------------------------------------------------------------------------
     * PRIVATE
     -------------------------------------------------------------------------------------------------*/
    private SecureBytes() {
        _bytes = new byte[0];
        return;
    }

    private boolean _compareMemoryToMemoryIn(SecureBytes secureBytesToCompareTo) {
        if(_bytes.length == secureBytesToCompareTo.getLength()) {
           return _compareEqualLengthByteArrays(_bytes, secureBytesToCompareTo.getByteRepresentation());
        } else {
            return false;
        }
    }

    private boolean _compareEqualLengthByteArrays(byte[] byteArrayOne, byte[] byteArrayTwo) {
        for(int index = 0; index < byteArrayOne.length; index++) {
            if(byteArrayOne[index] != byteArrayTwo[index]) {
                return false;
            }
        }
        return true;
    }

    /*-------------------------------------------------------------------------------------------------
     * PRIVATE STATIC
     -------------------------------------------------------------------------------------------------*/
    private static void _securelyCopyBytesFromIndexIntoBytesFromIndexWithLength(byte[] sourceBytes, int sourceStartIndex, 
        byte[] destinationBytes, int destinationStartIndex, int length) {
         _copyBytesFromIndexIntoBytesFromIndexWithLength(sourceBytes, sourceStartIndex, destinationBytes, destinationStartIndex, length);
        SecureEraser.eraseByteArray(sourceBytes);
    } // You do not include end indexes because lengths have to be the same, so having this parameter enforces them
      // to be the same
      // Think about what value is changing.. and how many values it has to go through

    private static void _copyBytesFromIndexIntoBytesFromIndexWithLength(byte[] sourceBytes, int sourceStartIndex, 
        byte[] destinationBytes, int destinationStartIndex, int length) {
        for(int index = 0; index < length; index++) {
            destinationBytes[destinationStartIndex + index] = sourceBytes[index + sourceStartIndex];
        }
    }
}