/*
 * CertificateTypeDoesntExistsException.java
 *
 * Created on 30 juli 2002, 11:27
 */

package se.anatom.ejbca.webdist.cainterface;

/**
 * An exception thrown when someone tries to change a certificate type that doesn't already exits
 *
 * @author  Philip Vendil
 */
public class CertificateTypeDoesntExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>CertificateTypeDoesntExistsException</code> without detail message.
     */
    public CertificateTypeDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CertificateTypeDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateTypeDoesntExistsException(String msg) {
        super(msg);
    }
}
