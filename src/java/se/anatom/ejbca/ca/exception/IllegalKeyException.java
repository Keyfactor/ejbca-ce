package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;

/**
 * Error due to malformed key.
 * The cause of failure can be related to illegal key length etc.
 *
 * @version $Id: IllegalKeyException.java,v 1.1 2002-11-18 11:18:22 anatom Exp $
 */
public class IllegalKeyException extends EjbcaException {

   /**
    * Constructor used to create exception with an errormessage.
    * Calls the same constructor in baseclass <code>Exception</code>.
    *
    * @param message Human redable error message, can not be NULL.
    */
   public IllegalKeyException(String message) {
       super(message);
   }
}
