/*
 * AdmingroupExistsException.java
 *
 * Created on den 23 mars 2002, 19:44
 */

package se.anatom.ejbca.authorization;

/**
 * An exception thrown when someone tries to add a admingroup that already exits
 *
 * @author  Philip Vendil
 * @version $Id: AdminGroupExistsException.java,v 1.1 2003-09-04 10:59:58 herrvendil Exp $
 */
public class AdminGroupExistsException extends java.lang.Exception {

    /**
     * Creates a new instance of <code>AdmingroupExistsException</code> without detail message.
     */
    public AdminGroupExistsException() {
        super();
    }


    /**
     * Constructs an instance of <code>AdmingroupExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public AdminGroupExistsException(String msg) {
        super(msg);
    }
}
