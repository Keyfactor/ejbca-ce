/*
 * ProfileDoesntExistsException.java
 *
 * Created on 13 juni 2002, 11:27
 */

package se.anatom.ejbca.ra.raadmin;

/**
 * An exception thrown when someone tries to add a profile that already exits
 *
 * @author  Philip Vendil
 */
public class ProfileDoesntExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>ProfileDoesntExistsException</code> without detail message.
     */
    public ProfileDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>ProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ProfileDoesntExistsException(String msg) {
        super(msg);
    }
}
