package security;

import org.junit.Test;
import static org.junit.Assert.*;

public class SecureEraserTest {

    @Test
    public void testErasingByteArrayStillKeepsByteArraySameLength() {
        byte[] bytes = {1, 1, 1, 1, 1};
        SecureEraser.eraseByteArray(bytes);
        assertTrue(bytes.length == 5);
    }

    @Test
    public void testErasingCharArrayStillKeepsCharArraySameLength() {
        char[] chars = {'c', 'c', 'c', 'c', 'c'};
        SecureEraser.eraseCharArray(chars);
        assertTrue(chars.length == 5);
    }
}