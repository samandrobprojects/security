package security;
/**
* This class represents secyre memory eraser
*
* <p> This class imeplements the ability to securely wipe memory data
*
* @author  Rob
* @author  Sam
*/

import java.util.ArrayList;

public class SecureEraser {

    private static final int _DELETE_ITERATIONS_FOR_SECURE_DATA_ERASING = 120;
    private static final int _DELETE_ITERATIONS_FOR_ERASING_RAM = 2;
    private static final int _MAX_BYTE_VALUE = 254;

    /*-------------------------------------------------------------------------------------------------
     * PUBLIC STATIC
     -------------------------------------------------------------------------------------------------*/

    /**
    * Erase a given byte array securely
    *
    * @param byteArrayToErase the byte array to erase
    */
    public static void eraseByteArray(byte[] byteArrayToErase) {
        if (!(byteArrayToErase == null)) {
            for (int numberDeleteIterations = 0; numberDeleteIterations < _DELETE_ITERATIONS_FOR_SECURE_DATA_ERASING; numberDeleteIterations++) {
                randomizeBytes(byteArrayToErase);
            }
        }
    }

    /**
    * Erase a given char array securely
    *
    * @param charArrayToErase the char array to erase
    */
    public static void eraseCharArray(char[] charArrayToErase) {
        if (!(charArrayToErase == null)) {
            for(int numberDeleteIterations = 0; numberDeleteIterations < _DELETE_ITERATIONS_FOR_SECURE_DATA_ERASING; numberDeleteIterations++) {
                randomizeCharacters(charArrayToErase);
            }
        }
    }

    /**
    * Erase all application RAM securely
    */
    public static void eraseAllApplciationMemory() {
        for(int ramEraseIterationNumber = 0; ramEraseIterationNumber < _DELETE_ITERATIONS_FOR_ERASING_RAM; ramEraseIterationNumber++) {
            wipeMemoryToCharacter((char) (ramEraseIterationNumber+96));
        }
    }

    /*-------------------------------------------------------------------------------------------------
     * PRIVATE STATIC
     -------------------------------------------------------------------------------------------------*/
    private static void randomizeCharacters(char[] charsToRandomize) {
        for (int characterIndex = 0; characterIndex < charsToRandomize.length; characterIndex++) {
            charsToRandomize[characterIndex] = (char) SecureRandomGenerator.generateRandomByteWithBound(_MAX_BYTE_VALUE);
        }
    }

    private static void randomizeBytes(byte[] bytesToRandomize) {
        for (int characterIndex = 0; characterIndex < bytesToRandomize.length; characterIndex++) {
            bytesToRandomize[characterIndex] = SecureRandomGenerator.generateRandomByteWithBound(_MAX_BYTE_VALUE);
        }
    }

    private static void wipeMemoryToCharacter(char characterToWipeTo) {
        ArrayList<SecureEraser.MemoryWipeObject> potentiallyInfiniteList = new ArrayList<SecureEraser.MemoryWipeObject>();
        try {
            while(true) {
                SecureEraser.MemoryWipeObject objectForWipe = new SecureEraser.MemoryWipeObject();
                objectForWipe.memoryByteToSet = (byte) characterToWipeTo;
                potentiallyInfiniteList.add(objectForWipe);
            }
        } catch(OutOfMemoryError e) {
            return;
        }
    }

    /**
    * This class represents the smallest possible object with a field
    *
    * <p> This class is used by the secure eraser in order to completely erase and wipe application RAM
    *   
    * @author  Rob
    * @author  Sam
    */
    private static class MemoryWipeObject {

        public byte memoryByteToSet;
    }
}
