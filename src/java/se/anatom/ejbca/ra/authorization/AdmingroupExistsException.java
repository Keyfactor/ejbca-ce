/*
 * AdmingroupExistsException.java
 *
 * Created on den 23 mars 2002, 19:44
 */
package se.anatom.ejbca.ra.authorization;

/**
 * An exception thrown when someone tries to add a admingroup that already exits
 *
 * @author Philip Vendil
 * @version $Id: AdmingroupExistsException.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public class AdmingroupExistsException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>AdmingroupExistsException</code> without detail message.
     */
    public AdmingroupExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>AdmingroupExistsException</code> with the specified detail
     * message.
     *
     * @param msg the detail message.
     */
    public AdmingroupExistsException(String msg) {
        super(msg);
    }
}
