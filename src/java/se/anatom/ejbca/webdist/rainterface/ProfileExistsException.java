/*
 * ProfileExistsException.java
 *
 * Created on 12 april 2002, 11:27
 */

package se.anatom.ejbca.webdist.rainterface;

/**
 * An exception thrown when someone tries to add a profile that already exits
 *
 * @author  Philip Vendil
 */
public class ProfileExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>ProfileExistsException</code> without detail message.
     */
    public ProfileExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>ProfileExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ProfileExistsException(String msg) {
        super(msg);
    }
}
