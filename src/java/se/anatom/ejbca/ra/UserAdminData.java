/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.ra;

import java.io.Serializable;

import java.util.Date;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.StringTools;

/**
 * Holds admin data collected from UserData in the database.
 *
 * @version $Id: UserAdminData.java,v 1.10 2004-04-16 07:38:56 anatom Exp $
 */
public class UserAdminData implements Serializable {

    // Public constants
    static final public int NO_ENDENTITYPROFILE    = 0;
    static final public int NO_CERTIFICATEPROFILE  = 0;


    private String username;
    private String subjectDN;
    private int caid;
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

    /**
     * Creates new UserAdminData. All fields are almos required in this constructor. Password must
     * be set amnually though. This is so you should be sure what you do with the password.
     *
     * @param user DOCUMENT ME!
     * @param dn DOCUMENT ME!
     * @param subjectaltname DOCUMENT ME!
     * @param email DOCUMENT ME!
     * @param status DOCUMENT ME!
     * @param type DOCUMENT ME!
     * @param endentityprofileid DOCUMENT ME!
     * @param certificateprofileid DOCUMENT ME!
     * @param timecreated DOCUMENT ME!
     * @param timemodified DOCUMENT ME!
     * @param tokentype DOCUMENT ME!
     * @param hardtokenissuerid DOCUMENT ME!
     */
    public UserAdminData(String user, String dn, int caid, String subjectaltname, String email, int status, int type, int endentityprofileid, int certificateprofileid,
                         Date timecreated, Date timemodified, int tokentype, int hardtokenissuerid) {
        this.username=StringTools.strip(user);
        this.password=null;
        this.subjectDN=dn;
        this.caid=caid;
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
    public void setUsername(String user) { this.username=StringTools.strip(user);}
    public String getUsername() {return username;}
    public void setDN(String dn) {this.subjectDN=dn;}
    public String getDN() {return subjectDN;}
    public int getCAId(){return this.caid;}
    public void setCAId(int caid){this.caid=caid;}
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
