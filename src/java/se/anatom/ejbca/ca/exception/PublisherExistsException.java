/*
 * PublisherExistsException.java
 *
 * Created on 26 november 2003, 21:29
 */

package se.anatom.ejbca.ca.exception;

/**
 * An exception thrown when someone tries to add a Publisher that already exits
 *
 * @author  Philip Vendil
 */
public class PublisherExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>PublisherExistsException</code> without detail message.
     */
    public PublisherExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>PublisherExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public PublisherExistsException(String msg) {
        super(msg);
    }
}
