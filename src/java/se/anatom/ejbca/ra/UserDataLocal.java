package se.anatom.ejbca.ra;

import java.security.NoSuchAlgorithmException;


/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataLocal.java,v 1.9 2003-06-26 11:43:24 anatom Exp $
 */
public interface UserDataLocal extends javax.ejb.EJBLocalObject {
    // Constants for Status of user
    public static final int STATUS_NEW = 10; // New user
    public static final int STATUS_FAILED = 11; // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = 20; // User has been initialized
    public static final int STATUS_INPROCESS = 30; // Generation of user certificate in process
    public static final int STATUS_GENERATED = 40; // A certificate has been generated for the user
    public static final int STATUS_REVOKED = 50; // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = 60; // The user is old and archived
    public static final int STATUS_KEYRECOVERY = 70; // The user is should use key recovery functions in next certificate generation.

    // public methods
    public String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public void setUsername(String username);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectDN();

//    public void setSubjectDN(String subjectDN);
    public String getSubjectAltName();

    /**
     * DOCUMENT ME!
     *
     * @param subjectAltName DOCUMENT ME!
     */
    public void setSubjectAltName(String subjectAltName);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getSubjectEmail();

    /**
     * DOCUMENT ME!
     *
     * @param subjectEmail DOCUMENT ME!
     */
    public void setSubjectEmail(String subjectEmail);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getStatus();

    /**
     * DOCUMENT ME!
     *
     * @param status DOCUMENT ME!
     */
    public void setStatus(int status);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getType();

    /**
     * DOCUMENT ME!
     *
     * @param type DOCUMENT ME!
     */
    public void setType(int type);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getClearPassword();

    /**
     * DOCUMENT ME!
     *
     * @param clearPassword DOCUMENT ME!
     */
    public void setClearPassword(String clearPassword);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getPasswordHash();

    /**
     * DOCUMENT ME!
     *
     * @param passwordHash DOCUMENT ME!
     */
    public void setPasswordHash(String passwordHash);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public long getTimeCreated();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public long getTimeModified();

    /**
     * DOCUMENT ME!
     *
     * @param createtime DOCUMENT ME!
     */
    public void setTimeModified(long createtime);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getEndEntityProfileId();

    /**
     * DOCUMENT ME!
     *
     * @param endentityprofileid DOCUMENT ME!
     */
    public void setEndEntityProfileId(int endentityprofileid);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getCertificateProfileId();

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofileid DOCUMENT ME!
     */
    public void setCertificateProfileId(int certificateprofileid);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getTokenType();

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     */
    public void setTokenType(int tokentype);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getHardTokenIssuerId();

    /**
     * DOCUMENT ME!
     *
     * @param hardtokenissuerid DOCUMENT ME!
     */
    public void setHardTokenIssuerId(int hardtokenissuerid);

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     */
    public void setDN(String dn);

    /**
     * DOCUMENT ME!
     *
     * @param password DOCUMENT ME!
     *
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     */
    public void setPassword(String password) throws NoSuchAlgorithmException;

    /**
     * DOCUMENT ME!
     *
     * @param password DOCUMENT ME!
     *
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     */
    public void setOpenPassword(String password) throws NoSuchAlgorithmException;

    /**
     * DOCUMENT ME!
     *
     * @param password DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     */
    public boolean comparePassword(String password) throws NoSuchAlgorithmException;
}
