/*
 * IllegalExtendedCAServiceRequestException.java
 *
 */

package se.anatom.ejbca.ca.caadmin.extendedcaservices;


public class IllegalExtendedCAServiceRequestException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>IllegalExtendedCAServiceRequestException</code> without detail message.
     */
    public IllegalExtendedCAServiceRequestException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>IllegalExtendedCAServiceRequestException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public IllegalExtendedCAServiceRequestException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>IllegalExtendedCAServiceRequestException</code> with the specified cause.
     * @param msg the detail message.
     */
    public IllegalExtendedCAServiceRequestException(Exception e) {
        super(e);
    }
}
