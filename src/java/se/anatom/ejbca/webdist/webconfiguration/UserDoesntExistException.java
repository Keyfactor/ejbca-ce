/*
 * UserDoesntExistException.java
 *
 * Created on den 28 mars 2002, 16:50
 */

package se.anatom.ejbca.webdist.webconfiguration;

/**
 * An exception thown when trying to change or remove a user that doesn't exists in the
 * database.
 *
 * @author  Philip Vendil
 */
public class UserDoesntExistException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>UserDoesntExistException</code> without detail message.
     */
    public UserDoesntExistException() {
      super();   
    }
    
    
    /**
     * Constructs an instance of <code>UserDoesntExistException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UserDoesntExistException(String msg) {
        super(msg);
    }
}
