package se.anatom.ejbca.util.passgen;

/**
 * IPasswordGenerator is an interface used to generate passwords used by end entities in EJBCA
 *
 * @version $Id: IPasswordGenerator.java,v 1.2 2003-12-05 14:49:10 herrvendil Exp $
 */
public interface IPasswordGenerator {
    
    /**
     *  Method generating a new password for the user and returns a string representation of it.
     * 
     * @param minlength indicates the minimun length of the generated password.
     * @param maxlength indicates the maximum length of the generated password.
     * @return the generated password
     */
    
    public abstract String getNewPassword(int minlength, int maxlength);
   
}
