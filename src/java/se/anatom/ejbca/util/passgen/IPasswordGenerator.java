package se.anatom.ejbca.util.passgen;

/**
 * IPasswordGenerator is an interface used to generate passwords used by end entities in EJBCA
 *
 * @version $Id: IPasswordGenerator.java,v 1.1 2003-10-21 13:48:47 herrvendil Exp $
 */
public interface IPasswordGenerator {
    
    /**
     *  Method generating a new password for the user and returns a string representation of it.
     * 
     * @return the generated password
     */
    
    public abstract String getNewPassword();
   
}
