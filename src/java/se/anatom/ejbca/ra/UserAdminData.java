package se.anatom.ejbca.ra;

import java.io.Serializable;
import java.util.Date;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.StringTools;


/**
 * Hols admin data collected from UserData in the database.
 *
 * @version $Id: UserAdminData.java,v 1.8 2003-07-24 08:43:31 anatom Exp $
 */
public class UserAdminData implements Serializable {
    // Public constants
    public static final int NO_ENDENTITYPROFILE = 0;
    public static final int NO_CERTIFICATEPROFILE = 0;
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

    /**
     * Creates new empty UserAdminData
     */
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
    public UserAdminData(String user, String dn, String subjectaltname, String email, int status,
        int type, int endentityprofileid, int certificateprofileid, Date timecreated,
        Date timemodified, int tokentype, int hardtokenissuerid) {
        this.username = StringTools.strip(user);
        this.password = null;
        this.subjectDN = dn;
        this.subjectAltName = subjectaltname;
        this.subjectEmail = email;
        this.status = status;
        this.type = type;
        this.endentityprofileid = endentityprofileid;
        this.certificateprofileid = certificateprofileid;
        this.timecreated = timecreated;
        this.timemodified = timemodified;
        this.tokentype = tokentype;
        this.hardtokenissuerid = hardtokenissuerid;
    }

    /**
     * DOCUMENT ME!
     *
     * @param user DOCUMENT ME!
     */
    public void setUsername(String user) {
        this.username = StringTools.strip(user);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername() {
        return username;
    }

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     */
    public void setDN(String dn) {
        this.subjectDN = dn;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getDN() {
        return subjectDN;
    }

    /**
     * DOCUMENT ME!
     *
     * @param subjectaltname DOCUMENT ME!
     */
    public void setSubjectAltName(String subjectaltname) {
        this.subjectAltName = subjectaltname;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectAltName() {
        return this.subjectAltName;
    }

    /**
     * DOCUMENT ME!
     *
     * @param email DOCUMENT ME!
     */
    public void setEmail(String email) {
        this.subjectEmail = email;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getEmail() {
        return subjectEmail;
    }

    /**
     * DOCUMENT ME!
     *
     * @param pwd DOCUMENT ME!
     */
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getPassword() {
        return password;
    }

    /**
     * DOCUMENT ME!
     *
     * @param status DOCUMENT ME!
     */
    public void setStatus(int status) {
        this.status = status;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getStatus() {
        return status;
    }

    /**
     * DOCUMENT ME!
     *
     * @param type DOCUMENT ME!
     */
    public void setType(int type) {
        this.type = type;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getType() {
        return type;
    }

    /**
     * DOCUMENT ME!
     *
     * @param endentityprofileid DOCUMENT ME!
     */
    public void setEndEntityProfileId(int endentityprofileid) {
        this.endentityprofileid = endentityprofileid;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getEndEntityProfileId() {
        return this.endentityprofileid;
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofileid DOCUMENT ME!
     */
    public void setCertificateProfileId(int certificateprofileid) {
        this.certificateprofileid = certificateprofileid;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getCertificateProfileId() {
        return this.certificateprofileid;
    }

    /**
     * DOCUMENT ME!
     *
     * @param timecreated DOCUMENT ME!
     */
    public void setTimeCreated(Date timecreated) {
        this.timecreated = timecreated;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getTimeCreated() {
        return this.timecreated;
    }

    /**
     * DOCUMENT ME!
     *
     * @param timemodified DOCUMENT ME!
     */
    public void setTimeModified(Date timemodified) {
        this.timemodified = timemodified;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getTimeModified() {
        return this.timemodified;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getTokenType() {
        return this.tokentype;
    }

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     */
    public void setTokenType(int tokentype) {
        this.tokentype = tokentype;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getHardTokenIssuerId() {
        return this.hardtokenissuerid;
    }

    /**
     * DOCUMENT ME!
     *
     * @param hardtokenissuerid DOCUMENT ME!
     */
    public void setHardTokenIssuerId(int hardtokenissuerid) {
        this.hardtokenissuerid = hardtokenissuerid;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getAdministrator() {
        return (type & SecConst.USER_ADMINISTRATOR) == SecConst.USER_ADMINISTRATOR;
    }

    /**
     * DOCUMENT ME!
     *
     * @param administrator DOCUMENT ME!
     */
    public void setAdministrator(boolean administrator) {
        if (administrator) {
            type = type | SecConst.USER_ADMINISTRATOR;
        } else {
            type = type & (~SecConst.USER_ADMINISTRATOR);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getKeyRecoverable() {
        return (type & SecConst.USER_KEYRECOVERABLE) == SecConst.USER_KEYRECOVERABLE;
    }

    /**
     * DOCUMENT ME!
     *
     * @param keyrecoverable DOCUMENT ME!
     */
    public void setKeyRecoverable(boolean keyrecoverable) {
        if (keyrecoverable) {
            type = type | SecConst.USER_KEYRECOVERABLE;
        } else {
            type = type & (~SecConst.USER_KEYRECOVERABLE);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getSendNotification() {
        return (type & SecConst.USER_SENDNOTIFICATION) == SecConst.USER_SENDNOTIFICATION;
    }

    /**
     * DOCUMENT ME!
     *
     * @param sendnotification DOCUMENT ME!
     */
    public void setSendNotification(boolean sendnotification) {
        if (sendnotification) {
            type = type | SecConst.USER_SENDNOTIFICATION;
        } else {
            type = type & (~SecConst.USER_SENDNOTIFICATION);
        }
    }
}
