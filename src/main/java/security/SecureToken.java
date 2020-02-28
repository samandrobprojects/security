package com.example.hydrus.security.secure_memory;
//--------------------------------------------------------------------------------------------
//
// AUTHOR
// ------
// Sam And Rob (2020)
//
//--------------------------------------------------------------------------------------------

public class SecureToken {

    private final static int _SECURE_TOKEN_LENGTH = 8;

    private byte[] _secureTokenByteArrays;

    //--------------------------------------------------------------------------------------
    // PUBLIC
    //--------------------------------------------------------------------------------------
    public void securelyDeleteBytes() {
        SecureEraser.eraseByteArray(this._secureTokenByteArrays);
    }

    public int getLength() {
        return _SECURE_TOKEN_LENGTH;
    }

    public byte[] getByteRepresentation() {
        byte[] byteRepresentation = _secureTokenByteArrays;
        return byteRepresentation;
    }

    //--------------------------------------------------------------------------------------
    // PUBLIC STATIC
    //--------------------------------------------------------------------------------------
    public static SecureToken secureTokenFromBytes(byte[] secureMessageBytes) {
        if(secureMessageBytes.length > _SECURE_TOKEN_LENGTH) return null;
        SecureToken secureToken = new SecureToken();
        secureToken._appendByteToInternalByteArray(secureMessageBytes);
        return secureToken;
    }

    public SecureToken copy() {
        byte[] byteCopy = new byte[_secureTokenByteArrays.length];
        for(int index = 0; index < _secureTokenByteArrays.length; index++) {
            byteCopy[index] = _secureTokenByteArrays[index];
        }
        return SecureToken.secureTokenFromBytes(byteCopy);
    }

    //--------------------------------------------------------------------------------------
    // PRIVATE
    //--------------------------------------------------------------------------------------
    private SecureToken() {
        return;
    }

    private void _appendByteToInternalByteArray(byte[] bytesToAppend) {
        this._secureTokenByteArrays = new byte[_SECURE_TOKEN_LENGTH];
        for(int bytesAdded = 0; bytesAdded < _SECURE_TOKEN_LENGTH; bytesAdded++) {
            this._secureTokenByteArrays[bytesAdded] = bytesToAppend[bytesAdded];
        }
        SecureEraser.eraseByteArray(bytesToAppend);
    }

    @Override
    protected void finalize() throws Throwable {
        this.securelyDeleteBytes();
        super.finalize();
    }
}