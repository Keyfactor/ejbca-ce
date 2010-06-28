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

package org.ejbca.core.ejb.ra;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;

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
 * Card Number (cardnumber)
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
 * @version $Id$
 *
 * @ejb.bean description="This enterprise bean entity represents a User Entry with accompanying data"
 * display-name="UserDataEB"
 * name="UserData"
 * jndi-name="UserData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="UserDataBean"
 *
 * @ejb.pk class="org.ejbca.core.ejb.ra.UserDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "UserData"
 * 
 * @ejb.transaction type="Required"
 * 
 * @ejb.home extends="javax.ejb.EJBHome"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.ejbca.core.ejb.ra.UserDataLocalHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.ejbca.core.ejb.ra.UserDataLocal"
 *
 * @ejb.finder
 *   description="findBySubjectDNAndCAId"
 *   signature="org.ejbca.core.ejb.ra.UserDataLocal findBySubjectDNAndCAId(java.lang.String subjectdn, int caId)"
 *   query="SELECT OBJECT(a) from UserDataBean a WHERE a.subjectDN=?1 AND a.caId=?2"
 *
 * @ejb.finder
 *   description="findBySubjectDN"
 *   signature="org.ejbca.core.ejb.ra.UserDataLocal findBySubjectDN(java.lang.String subjectdn)"
 *   query="SELECT OBJECT(a) from UserDataBean a WHERE a.subjectDN=?1"
 *   
 * @ejb.finder
 *   description="findBySubjectEmail"
 *   signature="java.util.Collection findBySubjectEmail(java.lang.String subjectEmail)"
 *   query="SELECT OBJECT(a) from UserDataBean a WHERE a.subjectEmail=?1"
 *
 * @ejb.finder
 *   description="findByStatus"
 *   signature="java.util.Collection findByStatus(int status)"
 *   query="SELECT OBJECT(a) from UserDataBean a WHERE a.status=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="java.util.Collection findAll()"
 *   query="SELECT OBJECT(a) from UserDataBean a"
 */
public abstract class UserDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(UserDataBean.class);


    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="username"
     * @ejb.interface-method
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence column-name="subjectDN"
     * @ejb.interface-method
     */
    public abstract String getSubjectDN();

    /**
     * @ejb.interface-method
     */
    public abstract void setSubjectDN(String subjectDN);

    /**
     * @ejb.persistence column-name="cAId"
     * @ejb.interface-method
     */
    public abstract int getCaId();

    /**
     * @ejb.interface-method
     */
    public abstract void setCaId(int caid);

    /**
     * @ejb.persistence column-name="subjectAltName"
     * @ejb.interface-method
     */
    public abstract String getSubjectAltName();

    /**
     * @ejb.interface-method
     */
    public abstract void setSubjectAltName(String subjectAltName);

    /**
     * @ejb.persistence column-name="cardnumber"
     * @ejb.interface-method
     */
    public abstract String getCardNumber();

    /**
     * @ejb.interface-method
     */
    public abstract void setCardNumber(String cardnumber);
    
    /**
     * @ejb.persistence column-name="subjectEmail"
     * @ejb.interface-method
     */
    public abstract String getSubjectEmail();

    /**
     * @ejb.interface-method
     */
    public abstract void setSubjectEmail(String subjectEmail);

    /**
     * @ejb.persistence column-name="status"
     * @ejb.interface-method
     */
    public abstract int getStatus();

    /**
     * @ejb.interface-method
     */
    public abstract void setStatus(int status);

    /**
     * @ejb.persistence column-name="type"
     * @ejb.interface-method
     */
    public abstract int getType();

    /**
     * @ejb.interface-method
     */
    public abstract void setType(int type);

    /**
     * Returns clear text password or null.
     *
     * @ejb.persistence column-name="clearPassword"
     * @ejb.interface-method
     */
    public abstract String getClearPassword();

    /**
     * Sets clear text password, the preferred method is setOpenPassword().
     *
     * @ejb.interface-method
     */
    public abstract void setClearPassword(String clearPassword);

    /**
     * Returns hashed password or null.
     *
     * @ejb.persistence column-name="passwordHash"
     * @ejb.interface-method
     */
    public abstract String getPasswordHash();

    /**
     * Sets hash of password, this is the normal way to store passwords, but use the method setPassword() instead.
     *
     * @ejb.interface-method
     */
    public abstract void setPasswordHash(String passwordHash);

    /**
     * Returns the time when the user was created.
     *
     * @ejb.persistence column-name="timeCreated"
     * @ejb.interface-method
     */
    public abstract long getTimeCreated();

    /**
     * Sets the time when the user was created.
     *
     */
    public abstract void setTimeCreated(long createtime);

    /**
     * Returns the time when the user was last modified.
     *
     * @ejb.persistence column-name="timeModified"
     * @ejb.interface-method
     */
    public abstract long getTimeModified();

    /**
     * Sets the time when the user was last modified.
     *
     * @ejb.interface-method
     */
    public abstract void setTimeModified(long createtime);

    /**
     * Returns the end entity profile id the user belongs to.
     *
     * @ejb.persistence column-name="endEntityProfileId"
     * @ejb.interface-method
     */
    public abstract int getEndEntityProfileId();

    /**
     * Sets the end entity profile id the user should belong to. 0 if profileid is not applicable.
     *
     * @ejb.interface-method
     */
    public abstract void setEndEntityProfileId(int endentityprofileid);

    /**
     * Returns the certificate profile id that should be generated for the user.
     *
     * @ejb.persistence column-name="certificateProfileId"
     * @ejb.interface-method
     */
    public abstract int getCertificateProfileId();

    /**
     * Sets the certificate profile id that should be generated for the user. 0 if profileid is not applicable.
     *
     * @ejb.interface-method
     */
    public abstract void setCertificateProfileId(int certificateprofileid);

    /**
     * Returns the token type id that should be generated for the user.
     *
     * @ejb.persistence column-name="tokenType"
     * @ejb.interface-method
     */
    public abstract int getTokenType();

    /**
     * Sets the token type  that should be generated for the user. Available token types can be found in SecConst.
     *
     * @ejb.interface-method
     */
    public abstract void setTokenType(int tokentype);

    /**
     * Returns the hard token issuer id that should genererate for the users hard token.
     *
     * @ejb.persistence column-name="hardTokenIssuerId"
     * @ejb.interface-method
     */
    public abstract int getHardTokenIssuerId();

    /**
     * Sets the hard token issuer id that should genererate for the users hard token. 0 if issuerid is not applicable.
     *
     * @ejb.interface-method
     */
    public abstract void setHardTokenIssuerId(int hardtokenissuerid);

    /**
     * Non-searchable information about a user.
     *
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="extendedInformationData"
     */
    public abstract String getExtendedInformationData();

    /**
     * Non-searchable information about a user.
     *
     */
    public abstract void setExtendedInformationData(String data);


    // Reserved for future use.
    /**
     * @ejb.persistence column-name="keyStorePassword"
     */
    public abstract String getKeyStorePassword();

    /**
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
        log.trace(">comparePassword()");
        boolean ret = false;
        if (password != null) {
            //log.debug("Newhash="+makePasswordHash(password)+", OldHash="+passwordHash);
            ret = (makePasswordHash(password).equals(getPasswordHash()));
        }
        log.trace("<comparePassword()");
        return ret;
    }


    //
    // Helper functions
    //



    /**
     * Creates the hashed password
     */

    private String makePasswordHash(String password) throws NoSuchAlgorithmException {
        log.trace(">makePasswordHash()");
        String ret = null;
        if (password != null) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA1");
                byte[] pwdhash = md.digest(password.trim().getBytes());
                ret = new String(Hex.encode(pwdhash));
            } catch (NoSuchAlgorithmException nsae) {
                log.error("SHA1 algorithm not supported.", nsae);
                throw nsae;
            }
        }
        log.trace("<makePasswordHash()");
        return ret;
    }


    /**
     * Non-searchable information about a user. 
     * @ejb.interface-method
     */
    public ExtendedInformation getExtendedInformation() {
        return UserDataVO.getExtendedInformation(getExtendedInformationData());
    }

    /**
     * Non-searchable information about a user. 
     * @ejb.interface-method
     */
    public void setExtendedInformation(ExtendedInformation extendedinformation) {
		try {
	    	String eidata = UserDataVO.extendedInformationToStringData(extendedinformation);
			setExtendedInformationData(eidata);
		} catch (UnsupportedEncodingException e) {
			throw new EJBException("Problems storing extended information for user :" + getUsername(), e);
		}	

    }

    /**
     * Non-searchable information about a user. 
     * @ejb.interface-method
     */
    public UserDataVO toUserDataVO() {
        UserDataVO data = new UserDataVO();
        data.setUsername(getUsername());
        data.setCAId(getCaId());
        data.setCertificateProfileId(getCertificateProfileId());
        data.setDN(getSubjectDN());
        data.setEmail(getSubjectEmail());
        data.setEndEntityProfileId(getEndEntityProfileId());
        data.setExtendedinformation(getExtendedInformation());
        data.setHardTokenIssuerId(getHardTokenIssuerId());
        data.setPassword(getClearPassword());
        data.setStatus(getStatus());
        data.setSubjectAltName(getSubjectAltName());
        data.setTimeCreated(new Date(getTimeCreated()));
        data.setTimeModified(new Date(getTimeModified()));
        data.setTokenType(getTokenType());
        data.setType(getType());
        data.setCardNumber(getCardNumber());
        return data;
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a User.
     * Create by sending in the instance, username, password, cardnumber and subject DN.
     * SubjectEmail, Status and Type are set to default values (null, STATUS_NEW, USER_INVALID).
     * and should be set using the respective set-methods. Clear text password is not set at all and must be set using setClearPassword();
     *
     * @param username   the unique username used for authentication.
     * @param password   the password used for authentication. This inly sets passwordhash, to set cleartext password, the setPassword() method must be used.
     * @param dn         the DN the subject is given in his certificate.
     * @param cardnumber the number printed on the card.
     * @return UserDataPK primary key
     * @ejb.create-method
     */
    public UserDataPK ejbCreate(String username, String password, String dn, int caid, String cardnumber)
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
        setCardNumber(cardnumber);
        UserDataPK pk = new UserDataPK(username);
        if (log.isDebugEnabled()) {        
        	log.debug("Created user " + username);
        }
        return pk;
    }

    public void ejbPostCreate(String username, String password, String dn, int caid, String cardnumber) {
        // Do nothing. Required.
    }
}
