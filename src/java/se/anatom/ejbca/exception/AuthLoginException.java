package se.anatom.ejbca.exception;

/**
 * Authentication error due to wrong credentials of user object.
 * To authenticate a user the user must have valid credentials, i.e. password.
 *
 * @version $Id: AuthLoginException.java,v 1.1 2002-03-22 10:11:24 anatom Exp $
 */
public class AuthLoginException extends Exception {

   /**
    * Constructor used to create exception with an errormessage.
    * Calls the same constructor in baseclass <code>Exception</code>.
    *
    * @param message Human redable error message, can not be NULL.
    */
   public AuthLoginException(String message) {
       super(message);
   }
}
