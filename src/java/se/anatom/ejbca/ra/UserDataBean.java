package se.anatom.ejbca.ra;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.util.StringTools;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Date;

import javax.ejb.CreateException;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * User. Information stored:
 * <pre>
 * Username (username)
 * SHA1 hash of password (passwordHash)
 * Clear text password if needed (clearPassword)
 * Subject DN (subjectDN)
 * Subject Alternative Name (subjectAltName
 * Subject Email (subjectEmail)
 * Status (status)
 * Type (type, from SecConst)
 * End Entity Profile (endEntityProfileId)
 * Certificate Profile (certificateProfileId)
 * Token Type (tokenType)
 * Hard Token Issuer (hardTokenIssuerId)
 * KeyStore Password (keyStorePassword), reserved for future use.
 * </pre>
 * Passwords should me manipulated through helper functions setPassword() and setOpenPassword().
 * The setPassword() function sets the hashed password, while the setOpenPassword() method sets
 * both the hashed password and the clear text password. The method comparePassword() is used to
 * verify a password againts the hashed password.
 *
 * @version $Id: UserDataBean.java,v 1.21 2003-06-26 11:43:24 anatom Exp $
 */
public abstract class UserDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(UserDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public abstract void setUsername(String username);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getSubjectDN();

    /**
     * DOCUMENT ME!
     *
     * @param subjectDN DOCUMENT ME!
     */
    public abstract void setSubjectDN(String subjectDN);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getSubjectAltName();

    /**
     * DOCUMENT ME!
     *
     * @param subjectAltName DOCUMENT ME!
     */
    public abstract void setSubjectAltName(String subjectAltName);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getSubjectEmail();

    /**
     * DOCUMENT ME!
     *
     * @param subjectEmail DOCUMENT ME!
     */
    public abstract void setSubjectEmail(String subjectEmail);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getStatus();

    /**
     * DOCUMENT ME!
     *
     * @param status DOCUMENT ME!
     */
    public abstract void setStatus(int status);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getType();

    /**
     * DOCUMENT ME!
     *
     * @param type DOCUMENT ME!
     */
    public abstract void setType(int type);

    /**
     * Returns clear text password or null.
     *
     * @return DOCUMENT ME!
     */
    public abstract String getClearPassword();

    /**
     * Sets clear text password, the preferred method is setOpenPassword().
     *
     * @see #setOpenPassword(String)
     */
    public abstract void setClearPassword(String clearPassword);

    /**
     * Returns hashed password or null.
     *
     * @return DOCUMENT ME!
     */
    public abstract String getPasswordHash();

    /**
     * Sets hash of password, this is the normal way to store passwords, but use the method
     * setPassword() instead.
     *
     * @see #setPassword(String)
     */
    public abstract void setPasswordHash(String passwordHash);

    /**
     * Returns the time when the user was created.
     *
     * @return DOCUMENT ME!
     */
    public abstract long getTimeCreated();

    /**
     * Sets the time when the user was created.
     */
    public abstract void setTimeCreated(long createtime);

    /**
     * Returns the time when the user was last modified.
     *
     * @return DOCUMENT ME!
     */
    public abstract long getTimeModified();

    /**
     * Sets the time when the user was last modified.
     */
    public abstract void setTimeModified(long createtime);

    /**
     * Returns the end entity profile id the user belongs to.
     *
     * @return DOCUMENT ME!
     */
    public abstract int getEndEntityProfileId();

    /**
     * Sets the end entity profile id the user should belong to. 0 if profileid is not applicable.
     */
    public abstract void setEndEntityProfileId(int endentityprofileid);

    /**
     * Returns the certificate profile id that should be generated for the user.
     *
     * @return DOCUMENT ME!
     */
    public abstract int getCertificateProfileId();

    /**
     * Sets the certificate profile id that should be generated for the user. 0 if profileid is not
     * applicable.
     */
    public abstract void setCertificateProfileId(int certificateprofileid);

    /**
     * Returns the token type id that should be generated for the user.
     *
     * @return DOCUMENT ME!
     */
    public abstract int getTokenType();

    /**
     * Sets the token type  that should be generated for the user. Available token types can be
     * found in SecConst.
     */
    public abstract void setTokenType(int tokentype);

    /**
     * Returns the hard token issuer id that should genererate for the users hard token.
     *
     * @return DOCUMENT ME!
     */
    public abstract int getHardTokenIssuerId();

    /**
     * Sets tthe hard token issuer id that should genererate for the users hard token. 0 if
     * issuerid is not applicable.
     */
    public abstract void setHardTokenIssuerId(int hardtokenissuerid);

    // Reserved for future use.
    public abstract String getKeyStorePassword();

    /**
     * DOCUMENT ME!
     *
     * @param keystorepassword DOCUMENT ME!
     */
    public abstract void setKeyStorePassword(String keystorepassword);

    //
    // Public methods used to help us manage passwords
    //

    /**
     * Function that sets the BCDN representation of the string.
     *
     * @param dn DOCUMENT ME!
     */
    public void setDN(String dn) {
        setSubjectDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * Sets password in ahsed form in the database, this way it cannot be read in clear form
     *
     * @param password DOCUMENT ME!
     */
    public void setPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(null);
    }

    /**
     * Sets the password in clear form in the database, needed for machine processing, also sets
     * the hashed password to the same value
     *
     * @param password DOCUMENT ME!
     */
    public void setOpenPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(password);
    }

    /**
     * Verifies password by verifying against passwordhash
     *
     * @param password DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean comparePassword(String password) throws NoSuchAlgorithmException {
        log.debug(">comparePassword()");

        if (password == null) {
            return false;
        }

        log.debug("<comparePassword()");

        //log.debug("Newhash="+makePasswordHash(password)+", OldHash="+passwordHash);
        return (makePasswordHash(password).equals(getPasswordHash()));
    }

    //
    // Helper functions
    //

    /**
     * Creates the hashed password
     *
     * @param password DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    private String makePasswordHash(String password) throws NoSuchAlgorithmException {
        log.debug(">makePasswordHash()");

        if (password == null) {
            return null;
        }

        String ret = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] pwdhash = md.digest(password.trim().getBytes());
            ret = Hex.encode(pwdhash);
        } catch (NoSuchAlgorithmException nsae) {
            log.error("SHA1 algorithm not supported.", nsae);
            throw nsae;
        }

        log.debug("<makePasswordHash()");

        return ret;
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a User. Create by sending in the instance, username, password
     * and subject DN. SubjectEmail, Status and Type are set to default values (null, STATUS_NEW,
     * USER_INVALID). and should be set using the respective set-methods. Clear text password is
     * not set at all and must be set using setClearPassword();
     *
     * @param username the unique username used for authentication.
     * @param password the password used for authentication. This inly sets passwordhash, to set
     *        cleartext password, the setPassword() method must be used.
     * @param dn the DN the subject is given in his certificate.
     *
     * @return UserDataPK primary key
     */
    public UserDataPK ejbCreate(String username, String password, String dn)
        throws CreateException, NoSuchAlgorithmException {
        long time = (new Date()).getTime();

        setUsername(StringTools.strip(username));
        setClearPassword(null);
        setPasswordHash(makePasswordHash(password));
        setSubjectDN(CertTools.stringToBCDNString(dn));
        setSubjectAltName(null);
        setSubjectEmail(null);
        setStatus(UserDataLocal.STATUS_NEW);
        setType(SecConst.USER_INVALID);
        setTimeCreated(time);
        setTimeModified(time);
        setEndEntityProfileId(0);
        setCertificateProfileId(0);
        setTokenType(SecConst.TOKEN_SOFT_BROWSERGEN);
        setHardTokenIssuerId(0);

        UserDataPK pk = new UserDataPK(username);
        log.debug("Created user " + username);

        return pk;
    }

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     * @param password DOCUMENT ME!
     * @param dn DOCUMENT ME!
     */
    public void ejbPostCreate(String username, String password, String dn) {
        // Do nothing. Required.
    }
}
