
package se.anatom.ejbca.ra;

import java.io.Serializable;
/**
 * Hols admin data collected from UserData in the database.
 *
 * @version $Id: UserAdminData.java,v 1.1.1.1 2001-11-15 14:58:17 anatom Exp $
 */
public class UserAdminData implements Serializable {

    private String username;
    private String subjectDN;
    private String subjectEmail;
    private String password;
    private int status;
    /** Type of user, from SecConst */
    private int type;

    /** Creates new empty UserAdminData */
    public UserAdminData() {
    }
    /** Creates new UserAdminData.
     * All fields are almos required in this constructor. Password must be set amnually though.
     * This is so you should be sure what you do with the password.
     */
    public UserAdminData(String user, String dn, String email, int status, int type) {
        this.username=user;
        this.password=null;
        this.subjectDN=dn;
        this.subjectEmail=email;
        this.status=status;
        this.type=type;
    }
    public void setUsername(String user) { this.username=user;}
    public String getUsername() {return username;}
    public void setDN(String dn) {this.subjectDN=dn;}
    public String getDN() {return subjectDN;}
    public void setEmail(String email) {this.subjectEmail = email;}
    public String getEmail() {return subjectEmail;}
    public void setPassword(String pwd) {this.password = pwd;}
    public String getPassword() {return password;}
    public void setStatus(int status) {this.status=status;}
    public int getStatus() {return status;}
    public void setType(int type) {this.type=type;}
    public int getType() {return type;}

}
