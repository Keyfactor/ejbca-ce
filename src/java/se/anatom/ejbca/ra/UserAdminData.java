package se.anatom.ejbca.ra;

import java.io.Serializable;

import java.util.Date;
import se.anatom.ejbca.SecConst;
/**
 * Hols admin data collected from UserData in the database.
 *
 * @version $Id: UserAdminData.java,v 1.5 2003-02-20 22:13:02 herrvendil Exp $
 */
public class UserAdminData implements Serializable {
    
    // Public constants
    static final public int NO_ENDENTITYPROFILE    = 0;
    static final public int NO_CERTIFICATEPROFILE  = 0;
    
    
    private String username;
    private String subjectDN;
    private String subjectAltName;
    private String subjectEmail;
    private String password;
    private int status;
    /** Type of user, from SecConst */
    private int type;
    private int endentityprofileid;
    private int certificateprofileid;
    private Date timecreated;
    private Date timemodified;
    private int tokentype;
    private int hardtokenissuerid;

    /** Creates new empty UserAdminData */
    public UserAdminData() {
    }
    /** Creates new UserAdminData.
     * All fields are almos required in this constructor. Password must be set amnually though.
     * This is so you should be sure what you do with the password.
     */
    public UserAdminData(String user, String dn, String subjectaltname, String email, int status, int type, int endentityprofileid, int certificateprofileid,
                         Date timecreated, Date timemodified, int tokentype, int hardtokenissuerid) {
        this.username=user;
        this.password=null;
        this.subjectDN=dn;
        this.subjectAltName=subjectaltname;
        this.subjectEmail=email;
        this.status=status;
        this.type=type;
        this.endentityprofileid=endentityprofileid;
        this.certificateprofileid=certificateprofileid;
        this.timecreated=timecreated;
        this.timemodified=timemodified;
        this.tokentype = tokentype;
        this.hardtokenissuerid = hardtokenissuerid;
    }
    public void setUsername(String user) { this.username=user;}
    public String getUsername() {return username;}
    public void setDN(String dn) {this.subjectDN=dn;}
    public String getDN() {return subjectDN;}
    public void setSubjectAltName( String subjectaltname) { this.subjectAltName=subjectaltname; }
    public String getSubjectAltName() {return this.subjectAltName;}
    public void setEmail(String email) {this.subjectEmail = email;}
    public String getEmail() {return subjectEmail;}
    public void setPassword(String pwd) {this.password = pwd;}
    public String getPassword() {return password;}
    public void setStatus(int status) {this.status=status;}
    public int getStatus() {return status;}
    public void setType(int type) {this.type=type;}
    public int getType() {return type;} 
    public void setEndEntityProfileId(int endentityprofileid) { this.endentityprofileid=endentityprofileid; }
    public int getEndEntityProfileId(){ return this.endentityprofileid; }
    public void setCertificateProfileId(int certificateprofileid) { this.certificateprofileid=certificateprofileid; }
    public int getCertificateProfileId() {return this.certificateprofileid;}
    public void setTimeCreated(Date timecreated) { this.timecreated=timecreated; }
    public Date getTimeCreated() {return this.timecreated;}    
    public void setTimeModified(Date timemodified) { this.timemodified=timemodified; }
    public Date getTimeModified() {return this.timemodified;} 
    public int getTokenType(){ return this.tokentype;}
    public void setTokenType(int tokentype) {this.tokentype=tokentype;}
    public int getHardTokenIssuerId() {return this.hardtokenissuerid;}
    public void setHardTokenIssuerId(int hardtokenissuerid) { this.hardtokenissuerid=hardtokenissuerid;}
    
    public boolean getAdministrator(){
      return (type & SecConst.USER_ADMINISTRATOR) == SecConst.USER_ADMINISTRATOR;  
    }
    
    public void setAdministrator(boolean administrator){
      if(administrator)
        type = type | SecConst.USER_ADMINISTRATOR;  
      else
        type = type & (~SecConst.USER_ADMINISTRATOR);  
    }
    
    public boolean getKeyRecoverable(){
      return (type & SecConst.USER_KEYRECOVERABLE) == SecConst.USER_KEYRECOVERABLE;          
    }
    
    public void setKeyRecoverable(boolean keyrecoverable){
      if(keyrecoverable)
        type = type | SecConst.USER_KEYRECOVERABLE;  
      else
        type = type & (~SecConst.USER_KEYRECOVERABLE);          
    }
    
    public boolean getSendNotification(){
      return (type & SecConst.USER_SENDNOTIFICATION) == SecConst.USER_SENDNOTIFICATION;          
    }
    
    public void setSendNotification(boolean sendnotification){
      if(sendnotification)
        type = type | SecConst.USER_SENDNOTIFICATION;  
      else
        type = type & (~SecConst.USER_SENDNOTIFICATION);          
    }
    
}
