/*
 * HardTokenProfileExistsException.java
 *
 * Created on 26 november 2003, 21:29
 */

package se.anatom.ejbca.hardtoken;

/**
 * An exception thrown when someone tries to add a hard token profile that already exits
 *
 * @author  Philip Vendil
 */
public class HardTokenProfileExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>HardTokenProfileExistsException</code> without detail message.
     */
    public HardTokenProfileExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>EHardTokenProfileExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public HardTokenProfileExistsException(String msg) {
        super(msg);
    }
}
