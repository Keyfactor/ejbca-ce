/*
 * CertificateProfileDoesntExistsException.java
 *
 * Created on 30 juli 2002, 11:27
 */

package se.anatom.ejbca.ca.exception;

/**
 * An exception thrown when someone tries to change a certificate profile that doesn't already exits
 *
 * @author  Philip Vendil
 */
public class CertificateProfileDoesntExistsException extends java.lang.Exception {
    
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
