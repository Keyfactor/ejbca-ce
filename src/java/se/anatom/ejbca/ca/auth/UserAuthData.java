
package se.anatom.ejbca.ca.auth;

import java.io.Serializable;
/**
 * Holds authentication data collected from an authentication source.
 *
 * @version $Id: UserAuthData.java,v 1.3 2002-12-05 19:42:07 anatom Exp $
 */
public class UserAuthData implements Serializable {

    private String username;
    private String subjectDN;
    private String subjectAltName;
    private String subjectEmail = null;
    private int    certProfileId = 0;
    /** type of user, from SecConst */
    private int type;

    /** Creates new empty UserAuthData */
    public UserAuthData() {
    }
    public UserAuthData(String user, String dn, String altName, String email, int type, int certProfileId) {
        this.username=user;
        this.subjectDN=dn;
        this.subjectAltName=altName;
        this.subjectEmail=email;
        this.type=type;
        this.certProfileId = certProfileId;
    }
    public void setUsername(String user) { this.username=user;}
    public String getUsername() {return username;}
    public void setDN(String dn) {this.subjectDN=dn;}
    public String getDN() {return subjectDN;}
    public void setAltName(String altName) {this.subjectAltName=altName;}
    public String getAltName() {return subjectAltName;}
    public void setEmail(String email) {this.subjectEmail = email;}
    public String getEmail() {return subjectEmail;}
    public void setType(int type) {this.type=type;}
    public int getType() {return type;}
    public void setCertProfileId(int certProfileId) {this.certProfileId=certProfileId;}
    public int getCertProfileId() {return certProfileId;}

}
