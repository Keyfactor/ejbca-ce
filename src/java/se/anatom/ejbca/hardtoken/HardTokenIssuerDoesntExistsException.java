/*
 * HardTokenIssuerExistsException.java
 *
 * Created on 20 januari 2003, 21:29
 */

package se.anatom.ejbca.hardtoken;

/**
 * An exception thrown when someone tries to remove or change a hard token issuer that doesn't exits
 *
 * @author  Philip Vendil
 */
public class HardTokenIssuerDoesntExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>HardTokenIssuerDoesntExistsException</code> without detail message.
     */
    public HardTokenIssuerDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>HardTokenIssuerDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public HardTokenIssuerDoesntExistsException(String msg) {
        super(msg);
    }
}
