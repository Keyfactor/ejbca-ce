package se.anatom.ejbca.util.query;

/**
 * An exception thrown if Query strucure is illegal.
 *
 * @author Philip Vendil
 * @version $Id: IllegalQueryException.java,v 1.2 2003-06-26 11:43:25 anatom Exp $
 */
public class IllegalQueryException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>IllegalQueryException</code> without detail message.
     */
    public IllegalQueryException() {
        super();
    }

    /**
     * Constructs an instance of <code>IllegalQueryException</code> with the specified detail
     * message.
     *
     * @param msg the detail message.
     */
    public IllegalQueryException(String msg) {
        super(msg);
    }
}
