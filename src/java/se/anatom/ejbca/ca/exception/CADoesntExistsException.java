package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;

/**
 * An exception thrown when someone tries to change a CA that doesn't already exits
 *
 * @author  Philip Vendil
 * @version $Id: CADoesntExistsException.java,v 1.3 2003-11-03 14:00:49 anatom Exp $
 */
public class CADoesntExistsException extends EjbcaException {
    
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

    /**
     * Constructs an instance of <code>CAProfileDoesntExistsException</code> with the specified cause.
     * @param msg the detail message.
     */
    public CADoesntExistsException(Exception e) {
        super(e);
    }
}
