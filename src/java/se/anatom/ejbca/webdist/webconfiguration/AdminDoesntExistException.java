/*
 * AdminDoesntExistException.java
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
public class AdminDoesntExistException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>AdminDoesntExistException</code> without detail message.
     */
    public AdminDoesntExistException() {
      super();   
    }
    
    
    /**
     * Constructs an instance of <code>AdminDoesntExistException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public AdminDoesntExistException(String msg) {
        super(msg);
    }
}
