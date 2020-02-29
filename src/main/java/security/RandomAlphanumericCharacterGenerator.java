package security;
/**
* This class represent a random alphanumeric character generator
*
* <p> This class is a secure random generator for alphanumeric characters
*
* @author  Rob
* @author  Sam
*/

import java.security.SecureRandom;
import java.util.Random;

/*
  These could include generators for standalone characters and bytes, but with length is more
  general because it covers all cases
*/

public class RandomAlphanumericCharacterGenerator {

    private static int _START_OF_ASCII_CHARACTERS = 97;
    private static int _NUMBER_OF_ASCII_CHARACTERS = 26;

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC STATIC
     -------------------------------------------------------------------------------------------------*/

    /**
    * Generate a byte array of random alphanumeric characters
    *
    * <p> This method creates a byte array of random alphanumeric characters of a given length
    *
    * @param length the number of alphanumeric characters to store in the byte array
    * @return the byte array of random alphanumeric characters
    */
    public static byte[] generateRandomAlphanumericCharacterByteArrayWithLength(int length) {
        byte[] randomAlphanumericCharacterByteArray = new byte[length];
        for(int index = 0; index < length; index++) {
            randomAlphanumericCharacterByteArray[index] = (byte) (SecureRandomGenerator.generateRandomByteWithBound(_NUMBER_OF_ASCII_CHARACTERS) + _START_OF_ASCII_CHARACTERS);
            System.out.println((int) randomAlphanumericCharacterByteArray[index]);
        }
        return randomAlphanumericCharacterByteArray;
    }

    /**
    * Generate a string of random alphanumeric characters
    *
    * <p> This method creates a string of random alphanumeric characters with a given length
    *
    * @param length the number of alphanumeric characters to store in the string
    * @return the string of random alphanumeric characters
    */
    public static String generateRandomAlphanumericCharacterStringWithLength(int length) {
        String randomAlphanumericCharacterString = "";
        for(int index = 0; index < length; index++) {
            char randomAlphanumericCharacter = (char) (SecureRandomGenerator.generateRandomByteWithBound(_NUMBER_OF_ASCII_CHARACTERS) + _START_OF_ASCII_CHARACTERS);
            randomAlphanumericCharacterString += Character.toString(randomAlphanumericCharacter);
        }
        return randomAlphanumericCharacterString;
    }
}
