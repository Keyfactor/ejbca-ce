/*
 * UserExistsException.java
 *
 * Created on den 28 mars 2002, 16:47
 */

package se.anatom.ejbca.webdist.webconfiguration;

/**
 * An exception thown when trying to add a user to the database that already
 * exists.
 *
 * @author  Philip Vendil
 */
public class UserExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>UserExistsException</code> without detail message.
     */
    public UserExistsException() {
       super();   
    }
    
    
    /**
     * Constructs an instance of <code>UserExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UserExistsException(String msg) {
        super(msg);
    }
}
