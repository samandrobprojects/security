package security;

import org.junit.Test;
import static org.junit.Assert.*;

public class SecureRandomGeneratorTest {

    @Test
    public void testRandomGenerationByteBoundWorks() {
        byte byteToTest;
        for(int i = 0; i < 1000; i++) {
            byteToTest = SecureRandomGenerator.generateRandomByteWithBound(2);
            assertTrue(byteToTest <= (byte) 2);
        }
    }

    @Test
    public void testRandomGenerationIntBoundWorks() {
        int intToTest;
        for(int i = 0; i < 1000; i++) {
            intToTest = SecureRandomGenerator.generateRandomIntWithBound(2);
            assertTrue(intToTest <= 2);
        }
    }

    @Test(expected = SecureRandomGeneratorBoundError.class)
    public void testGeneratingIntBoundExceptionThrownOnZero() {
        SecureRandomGenerator.generateRandomIntWithBound(0);
    }

    @Test(expected = SecureRandomGeneratorBoundError.class)
    public void testGeneratingIntBoundExceptionThrownOnNegative() {
        SecureRandomGenerator.generateRandomIntWithBound(-1);
    }

    @Test(expected = SecureRandomGeneratorBoundError.class)
    public void testGeneratingByteBoundExceptionThrownOnZero() {
        SecureRandomGenerator.generateRandomByteWithBound(0);
    }

    @Test(expected = SecureRandomGeneratorBoundError.class)
    public void testGeneratingByteBoundExceptionThrownOnNegative() {
        SecureRandomGenerator.generateRandomByteWithBound(1000);
    }
}
