package security;

import org.junit.Test;
import static org.junit.Assert.*;

public class SecureBytesTest {

    @Test public void testCreatingSecureBytesWithBytesReturnsCorrectBytes() {
        byte[] bytes = {1,1,1,1,1};
        SecureBytes secureBytes = SecureBytes.secureBytesFromBytes(bytes);
        assertTrue(secureBytes.getByteRepresentation().length == bytes.length);
        for(int index = 0; index < bytes.length; index++) {
            assertTrue(secureBytes.getByteRepresentation()[index] == (byte)1);
        }
    }

    @Test public void testCreatingEmptyBytesReturnsCorrectBytes() {
        SecureBytes secureBytes = SecureBytes.emptySecureBytes();
        assertTrue(secureBytes.getByteRepresentation().length == 0);
    }

    @Test public void testCreatingSecureBytesWithBytesAndAppendingReturnsCorrectBytes() {
        byte[] firstBytes = {1,1,1,1,1};
        byte[] secondBytes = {5, 5, 5, 5, 5};
        SecureBytes secureBytes = SecureBytes.secureBytesFromBytes(firstBytes);
        secureBytes.appendBytes(secondBytes);
        assertTrue(secureBytes.getByteRepresentation()[0] == (byte)1);
        assertTrue(secureBytes.getByteRepresentation()[1] == (byte)1);
        assertTrue(secureBytes.getByteRepresentation()[2] == (byte)1);
        assertTrue(secureBytes.getByteRepresentation()[3] == (byte)1);
        assertTrue(secureBytes.getByteRepresentation()[4] == (byte)1);
        assertTrue(secureBytes.getByteRepresentation()[5] == (byte)5);
        assertTrue(secureBytes.getByteRepresentation()[6] == (byte)5);
        assertTrue(secureBytes.getByteRepresentation()[7] == (byte)5);
        assertTrue(secureBytes.getByteRepresentation()[8] == (byte)5);
        assertTrue(secureBytes.getByteRepresentation()[9] == (byte)5);
        assertTrue(secureBytes.getByteRepresentation().length == 10);
    }
}
