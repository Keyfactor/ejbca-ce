package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;

/**
 * An exception thrown when someone tries to change or create a CA that doesn't already exits
 *
 * @author  Philip Vendil
 * @version $Id: CAExistsException.java,v 1.2 2003-11-03 14:00:49 anatom Exp $
 */
public class CAExistsException extends EjbcaException {
    
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
