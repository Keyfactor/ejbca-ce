/*
 * AuthorizationDeniedException.java
 *
 * Created on den 1 april 2002, 12:37
 */
package se.anatom.ejbca.ra.authorization;

/**
 * An exception thrown by the authenticate method in the EjbcaAthorization bean when authentication
 * of a given certificate failed.
 *
 * @author Philip Vendil
 */
public class AuthenticationFailedException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>AuthenticationDeniedException</code> without detail message.
     */
    public AuthenticationFailedException() {
        super();
    }

    /**
     * Constructs an instance of <code>AuthenticationDeniedException</code> with the specified
     * detail message.
     *
     * @param msg the detail message.
     */
    public AuthenticationFailedException(String msg) {
        super(msg);
    }
}
