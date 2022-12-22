/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.endentity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.ssh.SshEndEntityProfileFields;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.StringTools;
import org.cesecore.util.XmlSerializer;


/**
 * Holds admin data collected from UserData in the database. Strings are stored in Base64 encoded format to be safe for storing in database, xml etc.
 */
public class EndEntityInformation implements Serializable {

    private static final Logger log = Logger.getLogger(EndEntityInformation.class);

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = 3837505643343885941L;

    private String username;
    private String subjectDN;
    transient private String subjectDNClean = null;
    private int caid;
    private String subjectAltName;
    private String subjectEmail;
    private String password;
    private String cardNumber;
    /** Status of user, from {@link EndEntityConstants#STATUS_NEW} etc*/
    private int status;
    private int type;
    private int endentityprofileid;
    private int certificateprofileid;
    private Date timecreated;
    private Date timemodified;
    /** Type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc*/
    private int tokentype;
    /** ExtendedInformation holding extra data of the End entity */
    private ExtendedInformation extendedinformation;
    /** Indicates Subject DN and SAN merged with End Entity Profile*/
    private boolean profileMerged = false;
    
    /** Creates new empty EndEntityInformation */
    public EndEntityInformation() {
    }

    /**
     * Copy constructor for {@link EndEntityInformation}
     *
     * @param endEntityInformation an end entity to copy
     */
    public EndEntityInformation(final EndEntityInformation endEntityInformation) {
        this.username = endEntityInformation.getUsername();
        this.subjectDN = endEntityInformation.getDN();
        this.caid = endEntityInformation.getCAId();
        this.subjectAltName = endEntityInformation.getSubjectAltName();
        this.subjectEmail = endEntityInformation.getEmail();
        this.password = endEntityInformation.getPassword();
        this.cardNumber = endEntityInformation.getCardNumber();
        this.status = endEntityInformation.getStatus();
        this.type = endEntityInformation.getType().getHexValue();
        this.tokentype = endEntityInformation.getTokenType();
        this.endentityprofileid = endEntityInformation.getEndEntityProfileId();
        this.certificateprofileid = endEntityInformation.getCertificateProfileId();
        this.timecreated = endEntityInformation.getTimeCreated();
        this.timemodified = endEntityInformation.getTimeModified();
        this.tokentype = endEntityInformation.getTokenType();
        this.extendedinformation = (endEntityInformation.getExtendedInformation() != null ? new ExtendedInformation(endEntityInformation.getExtendedInformation()) : null);
        this.profileMerged = endEntityInformation.isProfileMerged();
    }

    /**
     * Creates new EndEntityInformation. All fields are almost required in this constructor. Password must
     * be set manually though. This is so you should be sure what you do with the password.
     *
     * @param username the unique username.
     * @param dn the DN the subject is given in his certificate.
     * @param caid CA id of the CA that the user is registered with
     * @param subjectaltname the Subject Alternative Name to be used.
     * @param email the email of the subject (may be null).
     * @param status Status of user, from {@link EndEntityConstants#STATUS_NEW} etc
     * @param type Type of user, {@link EndEntityTypes} contains a list. {@link EndEntityTypes#toEndEntityType} can be used to convert
     *          to the correct type, or you may combine multiple types using {@link EndEntityTypes#combineAll}.
     * @param endentityprofileid the id number of the end entity profile bound to this user.
     * @param certificateprofileid the id number of the certificate profile that should be generated for the user.
     * @param timecreated Deprecated since 7.3.2. Set to null.
     * @param timemodified Deprecated since 7.3.2. Set to null.
     * @param tokentype the type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc
     */
    public EndEntityInformation(final String username, final String dn, final int caid, final String subjectaltname, final String email,
            final int status, final EndEntityType type, final int endentityprofileid, final int certificateprofileid, final Date timecreated,
            final Date timemodified, final int tokentype, final ExtendedInformation extendedinfo) {
        setUsername(username);
        setPassword(null);
        setCardNumber(null);
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
        setExtendedInformation(extendedinfo);
        setCardNumber(null);
    }

    /**
     * Creates new EndEntityInformation. This constructor should only be used from UserDataSource
     * implementations. Status and dates aren't used in these cases.
     *
     * @param username the unique username.
     * @param dn the DN the subject is given in his certificate.
     * @param caid the id of the CA that should be used to issue the users certificate
     * @param subjectaltname the Subject Alternative Name to be used.
     * @param email the email of the subject (may be null).
     * @param type one of EndEntityTypes.USER_ENDUSER || ...
     * @param endentityprofileid the id number of the end entity profile bound to this user.
     * @param certificateprofileid the id number of the certificate profile that should be generated for the user.
     * @param tokentype the type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc
     * @param extendedinfo
     */
    public EndEntityInformation(final String username, final String dn, final int caid, final String subjectaltname, final String email,
            final EndEntityType type, final int endentityprofileid, final int certificateprofileid, final int tokentype, final ExtendedInformation extendedinfo) {
        setUsername(username);
        setPassword(null);
        setDN(dn);
        setCAId(caid);
        setSubjectAltName(subjectaltname);
        setEmail(email);
        setType(type);
        setEndEntityProfileId(endentityprofileid);
        setCertificateProfileId(certificateprofileid);
        setTokenType(tokentype);
        setExtendedInformation(extendedinfo);
        setCardNumber(null);
    }


    public void setUsername(String user) {
        this.username = StringTools.putBase64String(StringTools.stripUsername(user));
    }

    public String getUsername() {return StringTools.getBase64String(username);}
    public void setDN(String dn) {
        if (dn==null) {
            dn = "";
        }
    	final StringBuilder removedAllEmpties = new StringBuilder(dn.length());
        final StringBuilder removedTrailingEmpties = DNFieldsUtil.removeEmpties(dn, removedAllEmpties, true);
        if (removedTrailingEmpties == null) {
        	this.subjectDNClean=StringTools.putBase64String(removedAllEmpties.toString());
        	this.subjectDN=this.subjectDNClean;
    	} else {
        	this.subjectDNClean=StringTools.putBase64String(removedAllEmpties.toString());
        	this.subjectDN=StringTools.putBase64String(removedTrailingEmpties.toString());
    	}
    }

    /** User DN as stored in the database. If the registered DN has unused DN fields the empty ones are kept, i.e.
     * CN=Tomas,OU=,OU=PrimeKey,C=SE. See ECA-1841 for an explanation of this.
     * Use method getCertificateDN() to get the DN stripped from empty fields.
     * @see #getCertificateDN()
     * @return String with DN, might contain empty fields, use getCertificateDN to get without empty fields
     */
    public String getDN() {return StringTools.getBase64String(subjectDN);}
    public int getCAId(){return this.caid;}
    public void setCAId(int caid){this.caid=caid;}
    public void setSubjectAltName( String subjectaltname) { this.subjectAltName=StringTools.putBase64String(subjectaltname); }
    public String getSubjectAltName() {return StringTools.getBase64String(subjectAltName);}
    public void setEmail(String email) {this.subjectEmail = StringTools.putBase64String(email);}
    public String getEmail() {return StringTools.getBase64String(subjectEmail);}
    public void setCardNumber(String cardNumber) {this.cardNumber =  StringTools.putBase64String(cardNumber);}
    public String getCardNumber() {return StringTools.getBase64String(cardNumber);}
    public void setPassword(String pwd) {this.password = StringTools.putBase64String(pwd);}

    /**
     * Gets the user's clear text password. For empty passwords, it can either return
     * null or an empty string depending on the database software used.
     */
    public String getPassword() {return StringTools.getBase64String(password);}
    /** @param status Status of user, from {@link EndEntityConstants#STATUS_NEW} etc
     */
    public void setStatus(int status) {this.status=status;}
    public int getStatus() {return status;}
    public void setType(EndEntityType type) {this.type=type.getHexValue();}
    public EndEntityType getType() {return new EndEntityType(type);}
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

    /**
     * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This method is still used for deserializing objects in CertReqHistoryDataBean.
     */
    @Deprecated
    public boolean getAdministrator(){
      return getType().contains(EndEntityTypes.ADMINISTRATOR);
    }

    /**
     * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This method is still used for deserializing objects in CertReqHistoryDataBean.
     */
    @Deprecated
    public void setAdministrator(final boolean administrator) {
        final EndEntityType endEntityType = getType();
        if (administrator) {
            endEntityType.addType(EndEntityTypes.ADMINISTRATOR);
        } else {
            endEntityType.removeType(EndEntityTypes.ADMINISTRATOR);
        }
        setType(endEntityType);
    }

    public boolean getKeyRecoverable(){
        return getType().contains(EndEntityTypes.KEYRECOVERABLE);
    }

    public void setKeyRecoverable(final boolean keyrecoverable){
        final EndEntityType endEntityType = getType();
        if (keyrecoverable) {
            endEntityType.addType(EndEntityTypes.KEYRECOVERABLE);
        } else {
            endEntityType.removeType(EndEntityTypes.KEYRECOVERABLE);
        }
        setType(endEntityType);
    }

    public boolean getSendNotification(){
        return getType().contains(EndEntityTypes.SENDNOTIFICATION);
    }

    /** Sets flag (part of end entity type) that an email notification (triggered through the End Entity Profile) should be sent.
     * setSendNotification() must be called after setType(), because it adds to the type
     * @param sendnotification true or false
     */
    public void setSendNotification(final boolean sendnotification) {
        final EndEntityType endEntityType = getType();
        if (sendnotification) {
            endEntityType.addType(EndEntityTypes.SENDNOTIFICATION);
        } else {
            endEntityType.removeType(EndEntityTypes.SENDNOTIFICATION);
        }
        setType(endEntityType);
    }

    /**
     * @deprecated Printing support was removed in 8.0.0
     */
    @Deprecated
    public boolean getPrintUserData(){
        return getType().contains(EndEntityTypes.PRINT);
    }

    /**
     * @deprecated Printing support was removed in 8.0.0
     */
    @Deprecated
    public void setPrintUserData(final boolean printUserData){
        final EndEntityType endEntityType = getType();
        if (printUserData) {
            endEntityType.addType(EndEntityTypes.PRINT);
        } else {
            endEntityType.removeType(EndEntityTypes.PRINT);
        }
        setType(endEntityType);
    }
    
    public boolean isSshEndEntity(){
        return getType().contains(EndEntityTypes.SSH);
    }

    public void setSshEndEntity(final boolean sshEndEntity){
        final EndEntityType endEntityType = getType();
        if (sshEndEntity) {
            endEntityType.addType(EndEntityTypes.SSH);
            if(extendedinformation==null) {
                extendedinformation = new ExtendedInformation();
            }
            // sets to invalid value
            extendedinformation.setSshCustomData(SshEndEntityProfileFields.SSH_CERTIFICATE_TYPE, 0);
        } else {
            endEntityType.removeType(EndEntityTypes.SSH);
            if(extendedinformation!=null) {
                extendedinformation.removeSshCustomData(SshEndEntityProfileFields.SSH_CERTIFICATE_TYPE);
            }
        }
        setType(endEntityType);
    }

	/**
	 * @return Returns the extendedinformation or null if no extended information exists.
	 */
	public ExtendedInformation getExtendedInformation() {
		return extendedinformation;
	}
	/**
	 * @param extendedinformation The extendedinformation to set.
	 */
	public void setExtendedInformation(ExtendedInformation extendedinformation) {
		this.extendedinformation = extendedinformation;
	}

    /**
     * Help Method used to create an ExtendedInformation from String representation.
     * Used when creating an ExtendedInformation from queries.
     */
    public static ExtendedInformation getExtendedInformationFromStringData(final String extendedinfostring) {
        ExtendedInformation returnval = null;
        if (extendedinfostring != null && !extendedinfostring.isEmpty() ) {
            try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(extendedinfostring.getBytes(StandardCharsets.UTF_8)))) {
            	final HashMap<?, ?> data = (HashMap<?, ?>) decoder.readObject();
            	// No need to b64 decode Integer value, just read it
            	final int type = (Integer) data.get(ExtendedInformation.TYPE);
            	switch (type) {
            	case ExtendedInformation.TYPE_BASIC :
            	    returnval = new ExtendedInformation();
            	    returnval.loadData(data);
            	    break;
            	}
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to parse ExtendedInformation for End Entity. Data:\n" + extendedinfostring);
                }
                throw new IllegalStateException("Failed to parse ExtendedInformation data map for End Entity: " + e.getMessage(), e);
            }
        }
        return returnval;
    }

    public static String extendedInformationToStringData(final ExtendedInformation extendedinformation) {
    	String ret = null;
    	if (extendedinformation != null){
            // We must base64 encode string for UTF safety
            final LinkedHashMap<Object, Object> b64DataMap = new Base64PutHashMap();
            b64DataMap.putAll(extendedinformation.getRawData());
            // ECA-6284: Make fast XML serialization, under the assumption that extendedInformation is a simple map with string keys and primitive values 
            return XmlSerializer.encodeSimpleMapFast(b64DataMap);
            // The above replaces this, and takes a fraction of the time
            // try (final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);) {
            //   encoder.writeObject(b64DataMap);
            // }
    	}
    	return ret;
    }

    /** Returns the DN to be used when creating a certificate (without empty fields).
     * If the registered DN has unused DN fields the empty ones are kept, i.e.
     * CN=Tomas,OU=,OU=PrimeKey,C=SE. See ECA-1841 for an explanation of this.
     * Use method getCertificateDN() to get the DN stripped from empty fields, getDN() returns DN with empty fields.
     * @see #getDN()
     * @return String with DN, with no empty fields, use getDN to get including empty fields
     */
    public String getCertificateDN() {
    	if (subjectDNClean == null) {
    		// This might be fetched from database serialization so we need to perform the cleaning all over again
    		return DNFieldsUtil.removeAllEmpties(getDN());
    	} else {
            return StringTools.getBase64String(subjectDNClean);
    	}
    }

    /**
     * @return an information map about this end entity, listing all general fields.
     */
    public Map<String, String> getDetailMap() {
        @SuppressWarnings("unchecked")
        Map<String, String> details = new Base64GetHashMap();
        details.put("caid", Integer.toString(caid));
        details.put("cardnumber", cardNumber);
        details.put("certificateprofileid", Integer.toString(certificateprofileid));
        details.put("endentityprofileid", Integer.toString(endentityprofileid));
        if (extendedinformation != null) {
            StringBuilder extendedInformationDump = new StringBuilder("{");
            LinkedHashMap<Object, Object> rawData = extendedinformation.getRawData();
            for (Object key : rawData.keySet()) {
                if (rawData.get(key) != null) {
                    extendedInformationDump.append(", [").append((String) key).append(':').append(rawData.get(key)).append(']');
                }
            }
            extendedInformationDump.append("}");
            details.put("extendedInformation", extendedInformationDump.substring(2));
        }
        details.put("status", Integer.toString(status));
        details.put("subjectAltName", subjectAltName);
        details.put("subjectDN", subjectDN);
        details.put("subjectEmail", subjectEmail);
        if (timecreated != null) {
            details.put("timecreated", timecreated.toString());
        }
        if (timemodified != null) {
            details.put("timemodified", timemodified.toString());
        }
        details.put("tokentype", Integer.toString(tokentype));
        details.put("type", Integer.toString(type));
        details.put("username", username);
        return details;
    }

    /**
     *
     *
     * @param other another {@link EndEntityInformation}
     * @return the differences between this map and the parameter, as <key, [thisValue, otherValue]>
     */
    public Map<String, String[]> getDiff(EndEntityInformation other) {
        Map<String, String[]> changedValues = new LinkedHashMap<>();
        Map<String, String> thisValues = getDetailMap();
        Map<String, String> otherValues = other.getDetailMap();
        List<String> thisKeySet = new ArrayList<>(thisValues.keySet());
        for (String key : thisKeySet) {
            String thisValue = thisValues.get(key);
            String otherValue = otherValues.get(key);
            if (thisValue == null) {
                if (otherValue != null) {
                    changedValues.put(key, new String[] { "<null>", otherValue });
                }
            } else if (!thisValue.equals(otherValue)) {
                changedValues.put(key, new String[] { thisValue, otherValue });
            }
            thisValues.remove(key);
            otherValues.remove(key);
        }
        //Add in any values that may have been in otherValues but not here
        for (String otherKey : otherValues.keySet()) {
            changedValues.put(otherKey, new String[] { "<null>", otherValues.get(otherKey) });
        }
        return changedValues;
    }

    public boolean isProfileMerged() {
        return profileMerged;
    }

    public void setProfileMerged(boolean profileMerged) {
        this.profileMerged = profileMerged;
    }
    
}
