package security;

import org.junit.Test;
import static org.junit.Assert.*;

public class RandomAlphanumericCharacterGeneratorTest {

    @Test
    public void testByteGeneration() {
        byte[] randomArray = RandomAlphanumericCharacterGenerator.generateRandomAlphanumericCharacterByteArrayWithLength(5);
        for(int i = 0; i < 5; i++) {
            System.out.println((int)randomArray[i]);
            assertTrue((int) randomArray[i] >= (int) 97);
            assertTrue((int) randomArray[i] <= (int) 133);
        }
    }

    @Test
    public void testStringGeneration() {
        String randomString = RandomAlphanumericCharacterGenerator.generateRandomAlphanumericCharacterStringWithLength(5);
        for(int i = 0; i < 5; i++) {
            assertTrue((int) randomString.charAt(i) >= (int) 97);
            assertTrue((int) randomString.charAt(i) <= (int) 133);
        }
    }
}