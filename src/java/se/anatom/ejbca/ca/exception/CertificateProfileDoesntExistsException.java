package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;

/**
 * An exception thrown when someone tries to change a certificate profile that doesn't already exits
 *
 * @author  Philip Vendil
 * @version $Id: CertificateProfileDoesntExistsException.java,v 1.2 2003-11-03 14:00:49 anatom Exp $
 */
public class CertificateProfileDoesntExistsException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CertificateProfileDoesntExistsException</code> without detail message.
     */
    public CertificateProfileDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CertificateProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateProfileDoesntExistsException(String msg) {
        super(msg);
    }
}
