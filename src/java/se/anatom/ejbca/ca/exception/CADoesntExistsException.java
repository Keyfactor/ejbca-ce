/*
 * CADoesntExistsException.java
 *
 * Created on 17 august 2003, 11:27
 */

package se.anatom.ejbca.ca.exception;

/**
 * An exception thrown when someone tries to change a CA that doesn't already exits
 *
 * @author  Philip Vendil
 */
public class CADoesntExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>CADoesntExistsException</code> without detail message.
     */
    public CADoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CAProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CADoesntExistsException(String msg) {
        super(msg);
    }
}
