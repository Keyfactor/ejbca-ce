/*
 * AuthorizationDeniedException.java
 *
 * Created on den 1 april 2002, 12:37
 */
package se.anatom.ejbca.ra.authorization;

/**
 * An exception thrown by the isauthorized method in the EjbcaAthorization bean.
 *
 * @author Philip Vendil
 */
public class AuthorizationDeniedException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>AuthorizationDeniedException</code> without detail message.
     */
    public AuthorizationDeniedException() {
        super();
    }

    /**
     * Constructs an instance of <code>AuthorizationDeniedException</code> with the specified
     * detail message.
     *
     * @param msg the detail message.
     */
    public AuthorizationDeniedException(String msg) {
        super(msg);
    }
}
