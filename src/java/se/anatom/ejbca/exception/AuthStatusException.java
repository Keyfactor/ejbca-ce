package se.anatom.ejbca.exception;

/**
 * Authentication error due to wrong status of user object.
 * To authenticate a user the user must have status new, failed or inprocess.
 *
 * @version $Id: AuthStatusException.java,v 1.1 2002-03-22 10:11:24 anatom Exp $
 */
public class AuthStatusException extends Exception {

   /**
    * Constructor used to create exception with an errormessage.
    * Calls the same constructor in baseclass <code>Exception</code>.
    *
    * @param message Human redable error message, can not be NULL.
    */
   public AuthStatusException(String message) {
       super(message);
   }
}
