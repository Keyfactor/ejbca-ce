/*
 * HardTokenExistsException.java
 *
 * Created on 20 januari 2003, 21:29
 */
package se.anatom.ejbca.hardtoken;

/**
 * An exception thrown when someone tries to add a hard token that already exits
 *
 * @author Philip Vendil
 */
public class HardTokenExistsException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>HardTokenExistsException</code> without detail message.
     */
    public HardTokenExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>HardTokenExistsException</code> with the specified detail
     * message.
     *
     * @param msg the detail message.
     */
    public HardTokenExistsException(String msg) {
        super(msg);
    }
}
