/*
 * HardTokenIssuerExistsException.java
 *
 * Created on 20 januari 2003, 21:29
 */

package se.anatom.ejbca.hardtoken;

/**
 * An exception thrown when someone tries to add a hard token issuer that already exits
 *
 * @author  Philip Vendil
 */
public class HardTokenIssuerExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>HardTokenIssuerExistsException</code> without detail message.
     */
    public HardTokenIssuerExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>EHardTokenIssuerExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public HardTokenIssuerExistsException(String msg) {
        super(msg);
    }
}
