/*
 * CertificateTypeExistsException.java
 *
 * Created on 30 juli 2002, 11:27
 */

package se.anatom.ejbca.webdist.cainterface;

/**
 * An exception thrown when someone tries to add a CertificateType that already exits
 *
 * @author  Philip Vendil
 */
public class CertificateTypeExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>CertificateTypeExistsException</code> without detail message.
     */
    public CertificateTypeExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CertificateTypeExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateTypeExistsException(String msg) {
        super(msg);
    }
}
