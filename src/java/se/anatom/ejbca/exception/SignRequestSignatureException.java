package se.anatom.ejbca.exception;

/**
 * Error due to invlid signature on certificate request.
 *
 * @version $Id: SignRequestSignatureException.java,v 1.1 2002-03-22 10:11:24 anatom Exp $
 */
public class SignRequestSignatureException extends Exception {

   /**
    * Constructor used to create exception with an errormessage.
    * Calls the same constructor in baseclass <code>Exception</code>.
    *
    * @param message Human redable error message, can not be NULL.
    */
   public SignRequestSignatureException(String message) {
       super(message);
   }
}
