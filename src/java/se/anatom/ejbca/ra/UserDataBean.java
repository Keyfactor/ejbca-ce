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

import javax.ejb.CreateException;
import java.util.Date;
import java.util.HashMap;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.StringTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.Logger;

/** Entity bean should not be used directly, use though Session beans.
 *
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
 *
 * Passwords should me manipulated through helper functions setPassword() and setOpenPassword().
 * The setPassword() function sets the hashed password, while the setOpenPassword() method sets
 * both the hashed password and the clear text password.
 * The method comparePassword() is used to verify a password againts the hashed password.
 *
 * @version $Id: UserDataBean.java,v 1.26 2004-05-13 15:38:02 herrvendil Exp $
 */
public abstract class UserDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(UserDataBean.class);

    public abstract String getUsername();
    /** username must be called 'striped' using StringTools.strip()
    * @see se.anatom.ejbca.util.StringTools
    */
    public abstract void setUsername(String username);

    public abstract String getSubjectDN();
    public abstract void setSubjectDN(String subjectDN);
    
    public abstract int getCAId();
    public abstract void setCAId(int caid);

    public abstract String getSubjectAltName();
    public abstract void setSubjectAltName(String subjectAltName);

    public abstract String getSubjectEmail();
    public abstract void setSubjectEmail(String subjectEmail);

    public abstract int getStatus();
    public abstract void setStatus(int status);

    public abstract int getType();
    public abstract void setType(int type);

    /** Returns clear text password or null.
    */
    public abstract String getClearPassword();

    /** Sets clear text password, the preferred method is setOpenPassword().
     * @see #setOpenPassword(String)
     */
    public abstract void setClearPassword(String clearPassword);

    /** Returns hashed password or null.
    */
    public abstract String getPasswordHash();

    /** Sets hash of password, this is the normal way to store passwords, but use the method setPassword() instead.
     * @see #setPassword(String)
     */
    public abstract void setPasswordHash(String passwordHash);

    /**
     *  Returns the time when the user was created.
     */
    public abstract long getTimeCreated();

    /**
     * Sets the time when the user was created.
     */
    public abstract void setTimeCreated(long createtime);

    /**
     *  Returns the time when the user was last modified.
     */
    public abstract long getTimeModified();

    /**
     * Sets the time when the user was last modified.
     */
    public abstract void setTimeModified(long createtime);

    /**
     *  Returns the end entity profile id the user belongs to.
     */
    public abstract int getEndEntityProfileId();

    /**
     *  Sets the end entity profile id the user should belong to. 0 if profileid is not applicable.
     */
    public abstract void setEndEntityProfileId(int endentityprofileid);

    /**
     *  Returns the certificate profile id that should be generated for the user.
     */
    public abstract int getCertificateProfileId();

    /**
     *  Sets the certificate profile id that should be generated for the user. 0 if profileid is not applicable.
     */
    public abstract void setCertificateProfileId(int certificateprofileid);

    /**
     *  Returns the token type id that should be generated for the user.
     */
    public abstract int getTokenType();

    /**
     *  Sets the token type  that should be generated for the user. Available token types can be found in SecConst.
     */
    public abstract void setTokenType(int tokentype);

    /**
     *  Returns the hard token issuer id that should genererate for the users hard token.
     */
    public abstract int getHardTokenIssuerId();

    /**
     *  Sets tthe hard token issuer id that should genererate for the users hard token. 0 if issuerid is not applicable.
     */
    public abstract void setHardTokenIssuerId(int hardtokenissuerid);

    /**
     *  Non-searchable information about a user. for future use.
     */
    public abstract HashMap getExtendedInformationData();

    /**
     *  Non-searchable information about a user. for future use.
     */
    public abstract void setExtendedInformationData(HashMap data);    
    

    // Reserved for future use.
    public abstract String getKeyStorePassword();
    public abstract void setKeyStorePassword(String keystorepassword);


    //
    // Public methods used to help us manage passwords
    //

    /**
     * Function that sets the BCDN representation of the string.
     */
    public void setDN(String dn){
      setSubjectDN(CertTools.stringToBCDNString(dn));
    }

    /** Sets password in ahsed form in the database, this way it cannot be read in clear form */
    public void setPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(null);
    }

    /** Sets the password in clear form in the database, needed for machine processing,
     * also sets the hashed password to the same value
     */

    public void setOpenPassword(String password) throws NoSuchAlgorithmException {

        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(password);
    }

    /** Verifies password by verifying against passwordhash
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



    /** Creates the hashed password
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
     *  Non-searchable information about a user. for future use.
     */
    public  ExtendedInformation getExtendedInformation(){
      ExtendedInformation returnval = null;	
      if(getExtendedInformationData() != null){	
    	returnval = new ExtendedInformation();
        returnval.loadData(getExtendedInformationData());
      }  
      return returnval;
    }

    /**
     *  Non-searchable information about a user. for future use.
     */
    public void setExtendedInformation(ExtendedInformation extendedinformation){
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
     * @param dn the DN the subject is given in his certificate.
     * @return UserDataPK primary key
     *
     **/

    public UserDataPK ejbCreate(String username, String password, String dn, int caid)
       throws CreateException, NoSuchAlgorithmException {

        long time = (new Date()).getTime();

        setUsername(StringTools.strip(username));
        setClearPassword(null);
        setPasswordHash(makePasswordHash(password));
        setSubjectDN(CertTools.stringToBCDNString(dn));
        setCAId(caid);
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
        setExtendedInformationData(null);
        UserDataPK pk = new UserDataPK(username);
        log.debug("Created user "+username);

        return pk;
    }

    public void ejbPostCreate(String username, String password, String dn, int caid) {
        // Do nothing. Required.
    }
}
