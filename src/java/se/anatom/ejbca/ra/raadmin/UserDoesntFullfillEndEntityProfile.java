/*
 * UserDoesntFullfillEndEntityProfile.java
 *
 * Created on 12 april 2002, 11:27
 */

package se.anatom.ejbca.ra.raadmin;

/**
 * An exception thrown when someone tries to add or edit a profile that doesnt match its end entity profile.
 *
 * @author  Philip Vendil
 */
public class UserDoesntFullfillEndEntityProfile extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>UserDoesntFullfillProfile</code> without detail message.
     */
    public UserDoesntFullfillEndEntityProfile() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>UserDoesntFullfillProfile</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UserDoesntFullfillEndEntityProfile(String msg) {
        super(msg);
    }
}
