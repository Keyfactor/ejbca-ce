
package se.anatom.ejbca.ra;

import java.io.Serializable;

import java.util.Date;
/**
 * Hols admin data collected from UserData in the database.
 *
 * @version $Id: UserAdminData.java,v 1.3 2002-07-28 23:27:47 herrvendil Exp $
 */
public class UserAdminData implements Serializable {
    
    // Public constants
    static final public int NO_PROFILE         = 0;
    static final public int NO_CERTIFICATETYPE = 0;
    
    private String username;
    private String subjectDN;
    private String subjectEmail;
    private String password;
    private int status;
    /** Type of user, from SecConst */
    private int type;
    private int profileid;
    private int certificatetypeid;
    private Date timecreated;
    private Date timemodified;

    /** Creates new empty UserAdminData */
    public UserAdminData() {
    }
    /** Creates new UserAdminData.
     * All fields are almos required in this constructor. Password must be set amnually though.
     * This is so you should be sure what you do with the password.
     */
    public UserAdminData(String user, String dn, String email, int status, int type, int profileid, int certificatetypeid,
                         Date timecreated, Date timemodified) {
        this.username=user;
        this.password=null;
        this.subjectDN=dn;
        this.subjectEmail=email;
        this.status=status;
        this.type=type;
        this.profileid=profileid;
        this.certificatetypeid=certificatetypeid;
        this.timecreated=timecreated;
        this.timemodified=timemodified;
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
    public void setProfileId(int profileid) { this.profileid=profileid; }
    public int getProfileId(){ return this.profileid; }
    public void setCertificateTypeId(int certificatetyepid) { this.certificatetypeid=certificatetypeid; }
    public int getCertificateTypeId() {return this.certificatetypeid;}
    public void setTimeCreated(Date timecreated) { this.timecreated=timecreated; }
    public Date getTimeCreated() {return this.timecreated;}    
    public void setTimeModified(Date timemodified) { this.timemodified=timemodified; }
    public Date getTimeModified() {return this.timemodified;}        
}
