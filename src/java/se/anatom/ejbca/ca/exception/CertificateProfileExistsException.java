package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;

/**
 * An exception thrown when someone tries to add a certificate profile that already exits
 *
 * @author  Philip Vendil
 * @version $Id: CertificateProfileExistsException.java,v 1.2 2003-11-03 14:00:50 anatom Exp $
 */
public class CertificateProfileExistsException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CertificateProfileExistsException</code> without detail message.
     */
    public CertificateProfileExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CertificateProfileExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateProfileExistsException(String msg) {
        super(msg);
    }
}
