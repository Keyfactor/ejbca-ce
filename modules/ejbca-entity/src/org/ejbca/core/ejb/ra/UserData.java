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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;

/**
 * Representation of a User.
 * 
 * Passwords should me manipulated through helper functions setPassword() and setOpenPassword().
 * The setPassword() function sets the hashed password, while the setOpenPassword() method sets
 * both the hashed password and the clear text password.
 * The method comparePassword() is used to verify a password against the hashed password.
 * 
 * @version $Id$
 */
@Entity
@Table(name="UserData")
public class UserData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(UserData.class);

	private String username;
	private String subjectDN;
	private int caId;
	private String subjectAltName;
	private String cardNumber;
	private String subjectEmail;
	private int status;
	private int type;
	private String clearPassword;
	private String passwordHash;
	private long timeCreated;
	private long timeModified;
	private int endEntityProfileId;
	private int certificateProfileId;
	private int tokenType;
	private int hardTokenIssuerId;
	private String extendedInformationData;
	private String keyStorePassword;
	private int rowVersion = 0;
	private String rowProtection;

    /**
     * Entity Bean holding info about a User.
     * Create by sending in the instance, username, password and subject DN.
     * SubjectEmail, Status and Type are set to default values (null, STATUS_NEW, USER_INVALID).
     * and should be set using the respective set-methods. Clear text password is not set at all and must be set using setClearPassword();
     *
     * @param username the unique username used for authentication.
     * @param password   the password used for authentication. If clearpwd is false this only sets passwordhash, if clearpwd is true it also sets cleartext password.
     * @param clearpwd   true if clear password should be set for CA generated tokens (p12, jks, pem), false otherwise for only storing hashed passwords.
     * @param dn       the DN the subject is given in his certificate.
     * @param cardnumber the number printed on the card.
     * @param altname	string of alternative names, i.e. rfc822name=foo2bar.com,dnsName=foo.bar.com, can be null
     * @param email		user email address, can be null
     * @param type		user type, i.e. SecConst.USER_ENDUSER etc
     * @param eeprofileid	end entity profile id, can be 0
     * @param certprofileid	certificate profile id, can be 0
     * @param tokentype	token type to issue to the user, i.e. SecConst.TOKEN_SOFT_BROWSERGEN
     * @param hardtokenissuerid hard token issuer id if hard token issuing is used, 0 otherwise
     * @param extendedInformation ExtendedInformation object
     * 
     * @throws NoSuchAlgorithmException 
     */
    public UserData(String username, String password, boolean clearpwd, String dn, int caid, String cardnumber, String altname, String email,
    		int type, int eeprofileid, int certprofileid, int tokentype, int hardtokenissuerid, ExtendedInformation extendedInformation) 
    throws NoSuchAlgorithmException {
        long time = new Date().getTime();
        setUsername(StringTools.strip(username));
        if (clearpwd) {
        	setOpenPassword(password);
        } else {
            setPasswordHash(makePasswordHash(password));        	
            setClearPassword(null);
        }
        setSubjectDN(CertTools.stringToBCDNString(dn));
        setCaId(caid);
        setSubjectAltName(altname);
        setSubjectEmail(email);
        setStatus(UserDataConstants.STATUS_NEW);
        setType(type);
        setTimeCreated(time);
        setTimeModified(time);
        setEndEntityProfileId(eeprofileid);
        setCertificateProfileId(certprofileid);
        setTokenType(tokentype);
        setHardTokenIssuerId(hardtokenissuerid);
        setExtendedInformation(extendedInformation);
        setCardNumber(cardnumber);
        if (log.isDebugEnabled()) {        
        	log.debug("Created user " + username);
        }
    }

    public UserData()  { }

    //@Id @Column
    public String getUsername() { return username; }
    /**
     * username must be called 'striped' using StringTools.strip()
     */
    public void setUsername(String username) { this.username = username; }

    //@Column
    public String getSubjectDN() { return subjectDN; }
    public void setSubjectDN(String subjectDN) { this.subjectDN = subjectDN; }

    //@Column
    public int getCaId() { return caId; }
    public void setCaId(int caId) { this.caId = caId; }

    //@Column
    public String getSubjectAltName() { return subjectAltName; }
    public void setSubjectAltName(String subjectAltName) { this.subjectAltName = subjectAltName; }

    //@Column
    public String getCardNumber() { return cardNumber; }
    public void setCardNumber(String cardNumber) { this.cardNumber = cardNumber; }

    //@Column
    public String getSubjectEmail() { return subjectEmail; }
    public void setSubjectEmail(String subjectEmail) { this.subjectEmail = subjectEmail; }

    //@Column
    public int getStatus() { return this.status; }
    public void setStatus(int status) { this.status = status; }

    //@Column
    public int getType() { return type; }
    public void setType(int type) { this.type = type; }

    /**
     * Returns clear text password or null.
     */
    //@Column
    public String getClearPassword() { return clearPassword; }
    /**
     * Sets clear text password, the preferred method is setOpenPassword().
     */
    public void setClearPassword(String clearPassword) { this.clearPassword = clearPassword; }

    /**
     * Returns hashed password or null.
     */
    //@Column
    public String getPasswordHash() { return passwordHash; }
    /**
     * Sets hash of password, this is the normal way to store passwords, but use the method setPassword() instead.
     */
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    /**
     * Returns the time when the user was created.
     */
    //@Column
    public long getTimeCreated() { return timeCreated; }
    /**
     * Sets the time when the user was created.
     */
    public void setTimeCreated(long timeCreated) { this.timeCreated = timeCreated; }

    /**
     * Returns the time when the user was last modified.
     */
    //@Column
    public long getTimeModified() { return timeModified; }
    /**
     * Sets the time when the user was last modified.
     */
    public void setTimeModified(long timeModified) { this.timeModified = timeModified; }

    /**
     * Returns the end entity profile id the user belongs to.
     */
    //@Column
    public int getEndEntityProfileId() { return endEntityProfileId; }
    /**
     * Sets the end entity profile id the user should belong to. 0 if profileid is not applicable.
     */
    public void setEndEntityProfileId(int endEntityProfileId) { this.endEntityProfileId = endEntityProfileId; }

    /**
     * Returns the certificate profile id that should be generated for the user.
     */
    //@Column
    public int getCertificateProfileId() { return certificateProfileId; }
    /**
     * Sets the certificate profile id that should be generated for the user. 0 if profileid is not applicable.
     */
    public void setCertificateProfileId(int certificateProfileId) { this.certificateProfileId = certificateProfileId; }

    /**
     * Returns the token type id that should be generated for the user.
     */
    //@Column
    public int getTokenType() { return tokenType; }
    /**
     * Sets the token type  that should be generated for the user. Available token types can be found in SecConst.
     */
    public void setTokenType(int tokenType) { this.tokenType = tokenType; }

    /**
     * Returns the hard token issuer id that should genererate for the users hard token.
     */
    //@Column
    public int getHardTokenIssuerId() { return hardTokenIssuerId; }
    /**
     * Sets the hard token issuer id that should genererate for the users hard token. 0 if issuerid is not applicable.
     */
    public void setHardTokenIssuerId(int hardTokenIssuerId) { this.hardTokenIssuerId = hardTokenIssuerId; }

    /**
     * Non-searchable information about a user.
     */
    //@Column @Lob
    public String getExtendedInformationData() { return extendedInformationData; }
    /**
     * Non-searchable information about a user.
     */
    public void setExtendedInformationData(String extendedInformationData) { this.extendedInformationData = extendedInformationData; }

    @Deprecated	// Can't find any references to this field. Please un-deprecate if an use is discovered! =) 
    //@Column
    public String getKeyStorePassword() { return keyStorePassword; }
    @Deprecated	// Can't find any references to this field. Please un-deprecate if an use is discovered! =)
    public void setKeyStorePassword(String keyStorePassword) { this.keyStorePassword = keyStorePassword; }

    //@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    //
    // Public methods used to help us manage passwords
    //

    /**
     * Function that sets the BCDN representation of the string.
     */
    public void setDN(String dn) {
        setSubjectDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * Sets password in hashed form in the database, this way it cannot be read in clear form
     */
    public void setPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(null);
    }

    /**
     * Sets the password in clear form in the database, needed for machine processing,
     * also sets the hashed password to the same value
     */
    public void setOpenPassword(String password) throws NoSuchAlgorithmException {
        String passwordHash = makePasswordHash(password);
        setPasswordHash(passwordHash);
        setClearPassword(password);
    }

    /**
     * Verifies password by verifying against passwordhash
     */
    public boolean comparePassword(String password) throws NoSuchAlgorithmException {
    	if (log.isTraceEnabled()) {
    		log.trace(">comparePassword()");
    	}
        boolean ret = false;
        if (password != null) {
        	final String hash = getPasswordHash();
        	// Check if it is a new or old style hashing
        	if (StringUtils.startsWith(hash, "$2")) {
        		// new style with good salt
            	ret = BCrypt.checkpw(password, hash);        		
        	} else {
        		// old style, plain SHA1 hash
                ret = makeOldPasswordHash(password).equals(getPasswordHash());
        	}
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<comparePassword()");
    	}
        return ret;
    }

    //
    // Helper functions
    //

    /**
     * Creates the hashed password using the bcrypt algorithm, http://www.mindrot.org/projects/jBCrypt/
     */
    private String makePasswordHash(String password) throws NoSuchAlgorithmException {
        if (password == null) {
            return null;
        }
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    /**
     * Creates the hashed password using the old hashing, which is a plain SHA1 password
     */
    private String makeOldPasswordHash(String password) throws NoSuchAlgorithmException {
        if (password == null) {
            return null;
        }
        String ret = null;
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA1");
            final byte[] pwdhash = md.digest(password.trim().getBytes());
            ret = new String(Hex.encode(pwdhash));
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA1 algorithm not supported.", e);
            throw e;
        }
        return ret;
    }

    /**
     * Non-searchable information about a user.
     */
    @Transient
    public ExtendedInformation getExtendedInformation() {
        return UserDataVO.getExtendedInformation(getExtendedInformationData());
    }
    /**
     * Non-searchable information about a user.
     */
    public void setExtendedInformation(ExtendedInformation extendedinformation) {
		try {
	    	String eidata = UserDataVO.extendedInformationToStringData(extendedinformation);
			setExtendedInformationData(eidata);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Problems storing extended information for user :" + getUsername(), e);
		}	
    }
    
    /**
     * Non-searchable information about a user. 
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
    // Search functions. 
    //

	/** @return the found entity instance or null if the entity does not exist */
    public static UserData findByUsername(EntityManager entityManager, String username) {
    	if (username == null) {
    		return null;
    	}
    	return entityManager.find(UserData.class, username);
    }

	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
    public static UserData findBySubjectDNAndCAId(EntityManager entityManager, String subjectDN, int caId) {
    	UserData ret = null;
    	try {
    		Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN AND a.caId=:caId");
    		query.setParameter("subjectDN", subjectDN);
    		query.setParameter("caId", caId);
    		ret = (UserData) query.getSingleResult();
		} catch (NoResultException e) {
		}
		return ret;
    }    

	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
    public static UserData findBySubjectDN(EntityManager entityManager, String subjectDN) {
    	UserData ret = null;
    	try {
    		Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN");
    		query.setParameter("subjectDN", subjectDN);
    		ret = (UserData) query.getSingleResult();
		} catch (NoResultException e) {
		}
		return ret;
    }

	/** @return return the query results as a List. */
    public static List<UserData> findBySubjectEmail(EntityManager entityManager, String subjectEmail) {
    	Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectEmail=:subjectEmail");
    	query.setParameter("subjectEmail", subjectEmail);
    	return query.getResultList();
    }

	/** @return return the query results as a List. */
    public static List<UserData> findByStatus(EntityManager entityManager, int status) {
    	Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.status=:status");
    	query.setParameter("status", status);
    	return query.getResultList();
    }

	/** @return return the query results as a List. */
    public static List<UserData> findAll(EntityManager entityManager) {
    	Query query = entityManager.createQuery("SELECT a FROM UserData a");
    	return query.getResultList();
    }

	/** @return return the query results as a List. */
	public static List<UserData> findAllBatchUsersByStatus(EntityManager entityManager, int status, int maximumQueryRowcount) {
    	Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.status=:status AND (clearPassword IS NOT NULL)");
    	query.setParameter("status", status);
    	query.setMaxResults(maximumQueryRowcount);
    	return query.getResultList();
	}

	/** @return return a List<UserData> with tokenType TOKEN_HARD_DEFAULT and status NEW or KEYRECOVERY. */
	public static List<UserData> findNewOrKeyrecByHardTokenIssuerId(EntityManager entityManager, int hardTokenIssuerId, int maxResults) {
    	Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.hardTokenIssuerId=:hardTokenIssuerId AND a.tokenType>=:tokenType AND (a.status=:status1 OR a.status=:status2)");
    	query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
    	query.setParameter("tokenType", SecConst.TOKEN_HARD_DEFAULT);
    	query.setParameter("status1", UserDataConstants.STATUS_NEW);
    	query.setParameter("status2", UserDataConstants.STATUS_KEYRECOVERY);
    	if (maxResults > 0) {
    		query.setMaxResults(maxResults);
    	}
    	return query.getResultList();
	}
    
	/** @return return a count of UserDatas with tokenType TOKEN_HARD_DEFAULT and status NEW or KEYRECOVERY. */
	public static long countNewOrKeyrecByHardTokenIssuerId(EntityManager entityManager, int hardTokenIssuerId) {
    	Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.hardTokenIssuerId=:hardTokenIssuerId AND a.tokenType>=:tokenType AND (a.status=:status1 OR a.status=:status2)");
    	query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
    	query.setParameter("tokenType", SecConst.TOKEN_HARD_DEFAULT);
    	query.setParameter("status1", UserDataConstants.STATUS_NEW);
    	query.setParameter("status2", UserDataConstants.STATUS_KEYRECOVERY);
    	return ((Long)query.getSingleResult()).longValue();
	}

	/** @return return a count of UserDatas with tokenType TOKEN_HARD_DEFAULT and status NEW or KEYRECOVERY. */
	public static long countByHardTokenIssuerId(EntityManager entityManager, int hardTokenIssuerId) {
    	Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.hardTokenIssuerId=:hardTokenIssuerId");
    	query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
    	return ((Long)query.getSingleResult()).longValue();
	}

	public static String findSubjectEmailByUsername(EntityManager entityManager, String username) {
    	Query query = entityManager.createQuery("SELECT a.subjectEmail FROM UserData a WHERE a.username=:username");
    	query.setParameter("username", username);
		return (String) query.getSingleResult();
	}

	/** @return return a List<UserData> matching the custom query. */
	public static List<UserData> findByCustomQuery(EntityManager entityManager, String customQuery, int maxResults) {
    	Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE " + customQuery);
    	if (maxResults > 0) {
    		query.setMaxResults(maxResults);
    	}
    	return query.getResultList();
	}

	/** @return return a count of UserDatas with the specified End Entity Profile. */
	public static long countByEndEntityProfileId(EntityManager entityManager, int endEntityProfileId) {
    	Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.endEntityProfileId=:endEntityProfileId");
    	query.setParameter("endEntityProfileId", endEntityProfileId);
    	return ((Long)query.getSingleResult()).longValue();
	}

	/** @return return a count of UserDatas with the specified Certificate Profile. */
	public static long countByCertificateProfileId(EntityManager entityManager, int certificateProfileId) {
    	Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.certificateProfileId=:certificateProfileId");
    	query.setParameter("certificateProfileId", certificateProfileId);
    	return ((Long)query.getSingleResult()).longValue();
	}

	/** @return return a count of UserDatas with the specified CA. */
	public static long countByCaId(EntityManager entityManager, int caId) {
    	Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.caId=:caId");
    	query.setParameter("caId", caId);
    	return ((Long)query.getSingleResult()).longValue();
	}

	/** @return return a count of UserDatas with the specified Hard Token Profile. */
	public static long countByHardTokenProfileId(EntityManager entityManager, int hardTokenProfileId) {
    	Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.tokenType=:tokenType");
    	query.setParameter("tokenType", hardTokenProfileId);
    	return ((Long)query.getSingleResult()).longValue();
	}
}
