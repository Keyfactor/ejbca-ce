package se.anatom.ejbca.ca.auth;

import java.io.Serializable;

import se.anatom.ejbca.util.StringTools;


/**
 * Holds authentication data collected from an authentication source.
 *
 * @version $Id: UserAuthData.java,v 1.6 2003-07-24 08:43:30 anatom Exp $
 */
public class UserAuthData implements Serializable {
    private String username;
    private String subjectDN;
    private String subjectAltName;
    private String subjectEmail = null;
    private int certProfileId = 0;

    /** type of user, from SecConst */
    private int type;

    /**
     * Creates new empty UserAuthData
     */
    public UserAuthData() {
    }

    /**
     * Creates a new UserAuthData object.
     *
     * @param user username
     * @param dn DN for user
     * @param altName subject alternative names to be put in certificate
     * @param email email address
     * @param type type of user from SecConst (EndEntity, CA etc)
     * @param certProfileId the certificate profile the users certificate should be created with
     */
    public UserAuthData(String user, String dn, String altName, String email, int type,
        int certProfileId) {
        this.username = StringTools.strip(user);
        this.subjectDN = dn;
        this.subjectAltName = altName;
        this.subjectEmail = email;
        this.type = type;
        this.certProfileId = certProfileId;
    }

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @param user username
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public void setUsername(String user) {
        this.username = StringTools.strip(user);
    }

    /**
     * getter
     *
     * @return username
     */
    public String getUsername() {
        return username;
    }

    /**
     * setter
     *
     * @param dn DN
     */
    public void setDN(String dn) {
        this.subjectDN = dn;
    }

    /**
     * getter
     *
     * @return DN
     */
    public String getDN() {
        return subjectDN;
    }

    /**
     * setter
     *
     * @param altName altName
     */
    public void setAltName(String altName) {
        this.subjectAltName = altName;
    }

    /**
     * getter
     *
     * @return altName
     */
    public String getAltName() {
        return subjectAltName;
    }

    /**
     * setter
     *
     * @param email email
     */
    public void setEmail(String email) {
        this.subjectEmail = email;
    }

    /**
     * getter
     *
     * @return email
     */
    public String getEmail() {
        return subjectEmail;
    }

    /**
     * setter
     *
     * @param type type
     */
    public void setType(int type) {
        this.type = type;
    }

    /**
     * getter
     *
     * @return type
     */
    public int getType() {
        return type;
    }

    /**
     * setter
     *
     * @param certProfileId certificate profile id
     */
    public void setCertProfileId(int certProfileId) {
        this.certProfileId = certProfileId;
    }

    /**
     * getter
     *
     * @return certificate profile id
     */
    public int getCertProfileId() {
        return certProfileId;
    }
}
