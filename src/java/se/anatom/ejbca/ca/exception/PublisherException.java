package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;

/**
 * Is throw when error occured when publishing certificate, crl or revoking certificate to a publisher 
 *
 * @author  Philip Vendil
 * @version $Id: PublisherException.java,v 1.1 2004-03-07 12:08:08 herrvendil Exp $
 */
public class PublisherException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>PublisherException</code> without detail message.
     */
    public PublisherException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>PublisherException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public PublisherException(String msg) {
        super(msg);
    }
}
