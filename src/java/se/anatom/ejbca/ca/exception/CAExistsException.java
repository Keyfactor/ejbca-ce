/*
 * CAExistsException.java
 *
 * Created on 17 august 2003, 11:27
 */

package se.anatom.ejbca.ca.exception;

/**
 * An exception thrown when someone tries to change or create a CA that doesn't already exits
 *
 * @author  Philip Vendil
 */
public class CAExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>CAExistsException</code> without detail message.
     */
    public CAExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CAExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CAExistsException(String msg) {
        super(msg);
    }
}
