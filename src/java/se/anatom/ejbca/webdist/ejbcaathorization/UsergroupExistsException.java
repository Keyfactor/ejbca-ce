/*
 * UsergroupExistsException.java
 *
 * Created on den 23 mars 2002, 19:44
 */

package se.anatom.ejbca.webdist.ejbcaathorization;

/**
 * An exception thrown when someone tries to add a usergroup that already exits
 *
 * @author  Philip Vendil
 */
public class UsergroupExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>UserExistsException</code> without detail message.
     */
    public UsergroupExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>UserExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UsergroupExistsException(String msg) {
        super(msg);
    }
}
