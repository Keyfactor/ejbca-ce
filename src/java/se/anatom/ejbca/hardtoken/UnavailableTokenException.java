/*
 * UnavalableTokenException.java
 *
 * Created on 20 januari 2003, 21:29
 */

package se.anatom.ejbca.hardtoken;

/**
 * An exception thrown when issuer got a token is it's queue that isn't available to it.
 *
 * @author  Philip Vendil
 */
public class UnavailableTokenException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>UnavailableTokenException</code> without detail message.
     */
    public UnavailableTokenException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>UnavailableTokenException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UnavailableTokenException(String msg) {
        super(msg);
    }
}
