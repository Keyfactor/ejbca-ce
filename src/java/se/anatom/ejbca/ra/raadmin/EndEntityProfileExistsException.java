/*
 * EndEntityProfileExistsException.java
 *
 * Created on 12 april 2002, 11:27
 */
package se.anatom.ejbca.ra.raadmin;

/**
 * An exception thrown when someone tries to add a profile that already exits
 *
 * @author Philip Vendil
 */
public class EndEntityProfileExistsException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>EndEntityProfileExistsException</code> without detail
     * message.
     */
    public EndEntityProfileExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>EndEntityProfileExistsException</code> with the specified
     * detail message.
     *
     * @param msg the detail message.
     */
    public EndEntityProfileExistsException(String msg) {
        super(msg);
    }
}
