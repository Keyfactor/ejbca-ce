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
 
package org.ejbca.core.model.ra;

import java.io.Serializable;
import java.util.Date;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.StringTools;


/**
 * Holds admin data collected from UserData in the database. Strings are stored in Base64 encoded format to be safe for storing in database, xml etc.
 *
 * @version $Id: UserDataVO.java,v 1.4 2006-06-26 08:02:13 anatom Exp $
 */
public class UserDataVO implements Serializable {

    // Public constants
    public static final int NO_ENDENTITYPROFILE    = 0;
    public static final int NO_CERTIFICATEPROFILE  = 0;


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
    private ExtendedInformation extendedinformation;

    /** Creates new empty UserDataVO */
    public UserDataVO() {
    }

    /**
     * Creates new UserDataVO. All fields are almos required in this constructor. Password must
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
    public UserDataVO(String user, String dn, int caid, String subjectaltname, String email, int status, int type, int endentityprofileid, int certificateprofileid,
                         Date timecreated, Date timemodified, int tokentype, int hardtokenissuerid, ExtendedInformation extendedinfo) {
        setUsername(user);
        setPassword(null);
        setDN(dn);
        setCAId(caid);
        setSubjectAltName(subjectaltname);
        setEmail(email);
        setStatus(status);
        setType(type);
        setEndEntityProfileId(endentityprofileid);
        setCertificateProfileId(certificateprofileid);
        setTimeCreated(timecreated);
        setTimeModified(timemodified);
        setTokenType(tokentype);
        setHardTokenIssuerId(hardtokenissuerid);
        setExtendedinformation(extendedinfo);
    }
    public void setUsername(String user) { this.username=StringTools.putBase64String(StringTools.strip(user));}
    public String getUsername() {return StringTools.getBase64String(username);}
    public void setDN(String dn) {this.subjectDN=StringTools.putBase64String(dn);}
    public String getDN() {return StringTools.getBase64String(subjectDN);}
    public int getCAId(){return this.caid;}
    public void setCAId(int caid){this.caid=caid;}
    public void setSubjectAltName( String subjectaltname) { this.subjectAltName=StringTools.putBase64String(subjectaltname); }
    public String getSubjectAltName() {return StringTools.getBase64String(subjectAltName);}
    public void setEmail(String email) {this.subjectEmail = StringTools.putBase64String(email);}
    public String getEmail() {return StringTools.getBase64String(subjectEmail);}
    public void setPassword(String pwd) {this.password = StringTools.putBase64String(pwd);}
    public String getPassword() {return StringTools.getBase64String(password);}
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

	/**
	 * @return Returns the extendedinformation.
	 */
	public ExtendedInformation getExtendedinformation() {
		// If there is no extended information for this user, we return a new emtpy one
		if (extendedinformation == null) {
			return new ExtendedInformation();
		}
		return extendedinformation;
	}
	/**
	 * @param extendedinformation The extendedinformation to set.
	 */
	public void setExtendedinformation(ExtendedInformation extendedinformation) {
		this.extendedinformation = extendedinformation;
	}
}
