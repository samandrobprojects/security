package security;
/**
 * This class represents a bound parameter error for the SecureRandomGenerator class
 *
 * @author  Rob
 * @author  Sam
 */
public class SecureRandomGeneratorBoundError extends RuntimeException {

    public SecureRandomGeneratorBoundError(String errorMessage) {
        super(errorMessage);
    }
}
