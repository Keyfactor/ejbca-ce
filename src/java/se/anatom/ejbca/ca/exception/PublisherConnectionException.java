package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;

/**
 * Is throw when connection to a publisher have failed i some way.
 *
 * @author  Philip Vendil
 * @version $Id: PublisherConnectionException.java,v 1.1 2004-03-07 12:08:08 herrvendil Exp $
 */
public class PublisherConnectionException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>PublisherConnectionException</code> without detail message.
     */
    public PublisherConnectionException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>PublisherConnectionException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public PublisherConnectionException(String msg) {    	
        super(msg);        
    }
}
