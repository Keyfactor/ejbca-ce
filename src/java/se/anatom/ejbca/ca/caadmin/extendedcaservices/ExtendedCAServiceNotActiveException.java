/*
 * ExtendedCAServiceNotActiveException.java
 *
 * Created on 17 august 2003, 11:27
 */

package se.anatom.ejbca.ca.caadmin.extendedcaservices;


public class ExtendedCAServiceNotActiveException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>ExtendedCAServiceNotActiveException</code> without detail message.
     */
    public ExtendedCAServiceNotActiveException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>ExtendedCAServiceNotActiveException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ExtendedCAServiceNotActiveException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>IllegalExtendedServiceRequestException</code> with the specified cause.
     * @param msg the detail message.
     */
    public ExtendedCAServiceNotActiveException(Exception e) {
        super(e);
    }
}
