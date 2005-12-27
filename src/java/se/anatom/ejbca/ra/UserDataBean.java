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

import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.util.StringTools;

import javax.ejb.CreateException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;

/**
 * Entity bean should not be used directly, use though Session beans.
 * <p/>
 * Entity Bean representing a User.
 * Information stored:
 * <pre>
 * Username (username)
 * SHA1 hash of password (passwordHash)
 * Clear text password if needed (clearPassword)
 * Subject DN (subjectDN)
 * CAId of CA the user is belonging to.
 * Subject Alternative Name (subjectAltName
 * Subject Email (subjectEmail)
 * Status (status)
 * Type (type, from SecConst)
 * End Entity Profile (endEntityProfileId)
 * Certificate Profile (certificateProfileId)
 * Token Type (tokenType)
 * Hard Token Issuer (hardTokenIssuerId)
 * KeyStore Password (keyStorePassword), reserved for future use.
 * ExtendedInformation, extra information about a user.
 * </pre>
 * <p/>
 * Passwords should me manipulated through helper functions setPassword() and setOpenPassword().
 * The setPassword() function sets the hashed password, while the setOpenPassword() method sets
 * both the hashed password and the clear text password.
 * The method comparePassword() is used to verify a password againts the hashed password.
 *
 * @version $Id: UserDataBean.java,v 1.37 2005-12-27 14:18:56 anatom Exp $
 *
 * @ejb.bean description="This enterprise bean entity represents a Log Entry with accompanying data"
 * display-name="UserDataEB"
 * name="UserData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="UserDataBean"
 *
 * @ejb.pk class="se.anatom.ejbca.ra.UserDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="se.anatom.ejbca.ra.UserDataLocalHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject,UserDataConstants"
 * local-extends="javax.ejb.EJBLocalObject,UserDataConstants"
 * local-class="se.anatom.ejbca.ra.UserDataLocal"
 *
 * @ejb.finder
 *   description="findBySubjectDN"
 *   signature="se.anatom.ejbca.ra.UserDataLocal findBySubjectDN(java.lang.String username, int caId)"
 *   query="SELECT DISTINCT OBJECT(a) from UserDataBean a WHERE a.subjectDN=?1 AND a.caId=?2"
 *
 * @ejb.finder
 *   description="findBySubjectEmail"
 *   signature="java.util.Collection findBySubjectEmail(java.lang.String subjectEmail)"
 *   query="SELECT DISTINCT OBJECT(a) from UserDataBean a WHERE a.subjectEmail=?1"
 *
 * @ejb.finder
 *   description="findByStatus"
 *   signature="java.util.Collection findByStatus(int status)"
 *   query="SELECT DISTINCT OBJECT(a) from UserDataBean a WHERE a.status=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="java.util.Collection findAll()"
 *   query="SELECT DISTINCT OBJECT(a) from UserDataBean a"
 */
public abstract class UserDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(UserDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getSubjectDN();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setSubjectDN(String subjectDN);

    /**
     * @ejb.persistence column-name="cAId"
     * @ejb.interface-method
     */
    public abstract int getCaId();

    /**
     * @ejb.persistence column-name="cAId"
     * @ejb.interface-method
     */
    public abstract void setCaId(int caid);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getSubjectAltName();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setSubjectAltName(String subjectAltName);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getSubjectEmail();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setSubjectEmail(String subjectEmail);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getStatus();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setStatus(int status);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getType();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setType(int type);

    /**
     * Returns clear text password or null.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getClearPassword();

    /**
     * Sets clear text password, the preferred method is setOpenPassword().
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setClearPassword(String clearPassword);

    /**
     * Returns hashed password or null.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getPasswordHash();

    /**
     * Sets hash of password, this is the normal way to store passwords, but use the method setPassword() instead.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setPasswordHash(String passwordHash);

    /**
     * Returns the time when the user was created.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract long getTimeCreated();

    /**
     * Sets the time when the user was created.
     *
     * @ejb.persistence
     */
    public abstract void setTimeCreated(long createtime);

    /**
     * Returns the time when the user was last modified.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract long getTimeModified();

    /**
     * Sets the time when the user was last modified.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setTimeModified(long createtime);

    /**
     * Returns the end entity profile id the user belongs to.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getEndEntityProfileId();

    /**
     * Sets the end entity profile id the user should belong to. 0 if profileid is not applicable.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setEndEntityProfileId(int endentityprofileid);

    /**
     * Returns the certificate profile id that should be generated for the user.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getCertificateProfileId();

    /**
     * Sets the certificate profile id that should be generated for the user. 0 if profileid is not applicable.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setCertificateProfileId(int certificateprofileid);

    /**
     * Returns the token type id that should be generated for the user.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getTokenType();

    /**
     * Sets the token type  that should be generated for the user. Available token types can be found in SecConst.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setTokenType(int tokentype);

    /**
     * Returns the hard token issuer id that should genererate for the users hard token.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getHardTokenIssuerId();

    /**
     * Sets the hard token issuer id that should genererate for the users hard token. 0 if issuerid is not applicable.
     *
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setHardTokenIssuerId(int hardtokenissuerid);

    /**
     * Non-searchable information about a user. for future use.
     *
     * @ejb.persistence
     */
    public abstract HashMap getExtendedInformationData();

    /**
     * Non-searchable information about a user. for future use.
     *
     * @ejb.persistence
     */
    public abstract void setExtendedInformationData(HashMap data);


    // Reserved for future use.
    /**
     * @ejb.persistence
     */
    public abstract String getKeyStorePassword();

    /**
     * @ejb.persistence
     */
    public abstract void setKeyStorePassword(String keystorepassword);


    //
    // Public methods used to help us manage passwords
    //

    /**
     * Function that sets the BCDN representation of the string.
     * @ejb.interface-method
     */
    public void setDN(String dn) {
        setSubjectDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * Sets password in ahsed form in the database, this way it cannot be read in clear form
     * @ejb.interface-method
     */
    public void setPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(null);
    }

    /**
     * Sets the password in clear form in the database, needed for machine processing,
     * also sets the hashed password to the same value
     * @ejb.interface-method
     */
    public void setOpenPassword(String password) throws NoSuchAlgorithmException {

        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(password);
    }

    /**
     * Verifies password by verifying against passwordhash
     * @ejb.interface-method
     */
    public boolean comparePassword(String password) throws NoSuchAlgorithmException {
        log.debug(">comparePassword()");
        if (password == null)
            return false;

        log.debug("<comparePassword()");
        //log.debug("Newhash="+makePasswordHash(password)+", OldHash="+passwordHash);
        return (makePasswordHash(password).equals(getPasswordHash()));
    }


    //
    // Helper functions
    //



    /**
     * Creates the hashed password
     */

    private String makePasswordHash(String password) throws NoSuchAlgorithmException {
        log.debug(">makePasswordHash()");

        if (password == null)
            return null;

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


    /**
     * Non-searchable information about a user. for future use.
     * @ejb.interface-method
     */
    public ExtendedInformation getExtendedInformation() {
        ExtendedInformation returnval = null;
        if (getExtendedInformationData() != null) {
            returnval = new ExtendedInformation();
            returnval.loadData(getExtendedInformationData());
        }
        return returnval;
    }

    /**
     * Non-searchable information about a user. for future use.
     * @ejb.interface-method
     */
    public void setExtendedInformation(ExtendedInformation extendedinformation) {
        setExtendedInformationData((HashMap) extendedinformation.saveData());
    }
    
    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a User.
     * Create by sending in the instance, username, password and subject DN.
     * SubjectEmail, Status and Type are set to default values (null, STATUS_NEW, USER_INVALID).
     * and should be set using the respective set-methods. Clear text password is not set at all and must be set using setClearPassword();
     *
     * @param username the unique username used for authentication.
     * @param password the password used for authentication. This inly sets passwordhash, to set cleartext password, the setPassword() method must be used.
     * @param dn       the DN the subject is given in his certificate.
     * @return UserDataPK primary key
     * @ejb.create-method
     */
    public UserDataPK ejbCreate(String username, String password, String dn, int caid)
            throws CreateException, NoSuchAlgorithmException {

        long time = (new Date()).getTime();

        setUsername(StringTools.strip(username));
        setClearPassword(null);
        setPasswordHash(makePasswordHash(password));
        setSubjectDN(CertTools.stringToBCDNString(dn));
        setCaId(caid);
        setSubjectAltName(null);
        setSubjectEmail(null);
        setStatus(UserDataConstants.STATUS_NEW);
        setType(SecConst.USER_INVALID);
        setTimeCreated(time);
        setTimeModified(time);
        setEndEntityProfileId(0);
        setCertificateProfileId(0);
        setTokenType(SecConst.TOKEN_SOFT_BROWSERGEN);
        setHardTokenIssuerId(0);
        setExtendedInformationData(null);
        UserDataPK pk = new UserDataPK(username);
        log.debug("Created user " + username);

        return pk;
    }

    public void ejbPostCreate(String username, String password, String dn, int caid) {
        // Do nothing. Required.
    }
}