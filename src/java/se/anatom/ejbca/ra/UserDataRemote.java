package se.anatom.ejbca.ra;

import java.rmi.RemoteException;

import java.security.NoSuchAlgorithmException;


/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataRemote.java,v 1.7 2003-06-26 11:43:24 anatom Exp $
 */
public interface UserDataRemote extends javax.ejb.EJBObject {
    // Constants for Status of user
    public static final int STATUS_NEW = UserDataLocal.STATUS_NEW; // New user
    public static final int STATUS_FAILED = UserDataLocal.STATUS_FAILED; // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = UserDataLocal.STATUS_INITIALIZED; // User has been initialized
    public static final int STATUS_INPROCESS = UserDataLocal.STATUS_INPROCESS; // Generation of user certificate in process
    public static final int STATUS_GENERATED = UserDataLocal.STATUS_GENERATED; // A certificate has been generated for the user
    public static final int STATUS_REVOKED = UserDataLocal.STATUS_REVOKED; // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = UserDataLocal.STATUS_HISTORICAL; // The user is old and archived
    public static final int STATUS_KEYRECOVERY = UserDataLocal.STATUS_KEYRECOVERY; // The user is should use key recovery functions in next certificate generation.

    // public methods
    public String getUsername() throws RemoteException;

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public void setUsername(String username) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getSubjectDN() throws RemoteException;

//    public void setSubjectDN(String subjectDN) throws RemoteException;
    public String getSubjectAltName() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param subjectAltName DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setSubjectAltName(String subjectAltName)
        throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getSubjectEmail() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param subjectEmail DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setSubjectEmail(String subjectEmail) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getStatus() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param status DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setStatus(int status) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getType() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param type DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setType(int type) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getClearPassword() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param clearPassword DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setClearPassword(String clearPassword)
        throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getPasswordHash() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param passwordHash DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setPasswordHash(String passwordHash) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public long getTimeCreated() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public long getTimeModified() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param createtime DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setTimeModified(long createtime) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getEndEntityProfileId() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param endentityprofileid DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setEndEntityProfileId(int endentityprofileid)
        throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getCertificateProfileId() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofileid DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setCertificateProfileId(int certificateprofileid)
        throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getTokenType() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param tokentype DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setTokenType(int tokentype) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getHardTokenIssuerId() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param hardtokenissuerid DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setHardTokenIssuerId(int hardtokenissuerid)
        throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setDN(String dn) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param password DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     */
    public void setPassword(String password) throws RemoteException, NoSuchAlgorithmException;

    /**
     * DOCUMENT ME!
     *
     * @param password DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     */
    public void setOpenPassword(String password) throws RemoteException, NoSuchAlgorithmException;

    /**
     * DOCUMENT ME!
     *
     * @param password DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     */
    public boolean comparePassword(String password)
        throws RemoteException, NoSuchAlgorithmException;
}
