
package se.anatom.ejbca.ca.auth;

import java.io.Serializable;
/**
 * Holds authentication data collected from an authentication source.
 *
 * @version $Id: UserAuthData.java,v 1.1.1.1 2001-11-15 14:58:14 anatom Exp $
 */
public class UserAuthData implements Serializable {

    private String username;
    private String subjectDN;
    private String subjectEmail;
    /** type of user, from SecConst */
    private int type;

    /** Creates new empty UserAuthData */
    public UserAuthData() {
    }
    public UserAuthData(String user, String dn, String email, int type) {
        this.username=user;
        this.subjectDN=dn;
        this.subjectEmail=email;
        this.type=type;
    }
    public void setUsername(String user) { this.username=user;}
    public String getUsername() {return username;}
    public void setDN(String dn) {this.subjectDN=dn;}
    public String getDN() {return subjectDN;}
    public void setEmail(String email) {this.subjectEmail = email;}
    public String getEmail() {return subjectEmail;}
    public void setType(int type) {this.type=type;}
    public int getType() {return type;}

}
