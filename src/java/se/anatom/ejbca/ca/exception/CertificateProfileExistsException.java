/*
 * CertificateProfileExistsException.java
 *
 * Created on 30 juli 2002, 11:27
 */

package se.anatom.ejbca.ca.exception;

/**
 * An exception thrown when someone tries to add a certificate profile that already exits
 *
 * @author  Philip Vendil
 */
public class CertificateProfileExistsException extends java.lang.Exception {
    
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
