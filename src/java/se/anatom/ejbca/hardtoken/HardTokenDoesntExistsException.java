/*
 * HardTokenDoesntExistsException.java
 *
 * Created on 20 januari 2003, 21:29
 */
package se.anatom.ejbca.hardtoken;

/**
 * An exception thrown when someone tries to remove or change a hard token that doesn't exits
 *
 * @author Philip Vendil
 */
public class HardTokenDoesntExistsException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>HardTokenDoesntExistsException</code> without detail
     * message.
     */
    public HardTokenDoesntExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>HardTokenDoesntExistsException</code> with the specified
     * detail message.
     *
     * @param msg the detail message.
     */
    public HardTokenDoesntExistsException(String msg) {
        super(msg);
    }
}
