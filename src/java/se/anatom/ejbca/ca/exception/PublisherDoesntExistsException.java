/*
 * PublisherDoesntExistsException.java
 *
 * Created on 20 januari 2003, 21:29
 */

package se.anatom.ejbca.ca.exception;

/**
 * An exception thrown when someone tries to remove or change a Publisher that doesn't exits
 *
 * @author  Philip Vendil
 * @version
 */
public class PublisherDoesntExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>PublisherDoesntExistsException</code> without detail message.
     */
    public PublisherDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>PublisherDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public PublisherDoesntExistsException(String msg) {
        super(msg);
    }
}
