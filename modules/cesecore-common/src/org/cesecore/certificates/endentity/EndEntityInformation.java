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
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.StringTools;


/**
 * Holds admin data collected from UserData in the database. Strings are stored in Base64 encoded format to be safe for storing in database, xml etc.
 *
 * @version $Id$
 */
public class EndEntityInformation implements Serializable {

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

    // Public constants
    public static final int NO_ENDENTITYPROFILE    = 0;
    public static final int NO_CERTIFICATEPROFILE  = 0;


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
    private int hardtokenissuerid;
    /** ExtendedInformation holding extra data of the End entity */
    private ExtendedInformation extendedinformation;

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
     * @param type Type of user, from {@link EndEntityConstants#ENDUSER} etc, can be "or:ed" together, i.e. EndEntityConstants#USER_ENDUSER | {@link EndEntityConstants#SENDNOTIFICATION}
     * @param endentityprofileid the id number of the end entity profile bound to this user.
     * @param certificateprofileid the id number of the certificate profile that should be generated for the user.
     * @param timecreated DOCUMENT ME!
     * @param timemodified DOCUMENT ME!
     * @param tokentype the type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc
     * @param hardtokenissuerid if token should be hard, the id of the hard token issuer, else 0.

     */
    public EndEntityInformation(final String username, final String dn, final int caid, final String subjectaltname, final String email,
            final int status, final EndEntityType type, final int endentityprofileid, final int certificateprofileid, final Date timecreated,
            final Date timemodified, final int tokentype, final int hardtokenissuerid, final ExtendedInformation extendedinfo) {
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
        setHardTokenIssuerId(hardtokenissuerid);
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
     * @param hardtokenissuerid if token should be hard, the id of the hard token issuer, else 0.
     * @param extendedinfo
     */
    public EndEntityInformation(final String username, final String dn, final int caid, final String subjectaltname, final String email,
            final EndEntityType type, final int endentityprofileid, final int certificateprofileid, final int tokentype, final int hardtokenissuerid,
            final ExtendedInformation extendedinfo) {
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
        setHardTokenIssuerId(hardtokenissuerid);
        setExtendedInformation(extendedinfo);
        setCardNumber(null);
    }


    public void setUsername(String user) { this.username=StringTools.putBase64String(StringTools.stripUsername(user));}
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
    public int getHardTokenIssuerId() {return this.hardtokenissuerid;}
    public void setHardTokenIssuerId(int hardtokenissuerid) { this.hardtokenissuerid=hardtokenissuerid;}


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
    public void setAdministrator(final boolean administrator){
        final EndEntityType type = getType();
        if (administrator) {
            type.addType(EndEntityTypes.ADMINISTRATOR);
        } else {
            type.removeType(EndEntityTypes.ADMINISTRATOR);
        }
        setType(type);
    }

    public boolean getKeyRecoverable(){
        return getType().contains(EndEntityTypes.KEYRECOVERABLE);
    }

    public void setKeyRecoverable(final boolean keyrecoverable){
        final EndEntityType type = getType();
        if (keyrecoverable) {
            type.addType(EndEntityTypes.KEYRECOVERABLE);
        } else {
            type.removeType(EndEntityTypes.KEYRECOVERABLE);
        }
        setType(type);
    }

    public boolean getSendNotification(){
        return getType().contains(EndEntityTypes.SENDNOTIFICATION);
    }

    /** Sets flag (part of end entity type) that an email notification (triggered through the End Entity Profile) should be sent.
     * setSendNotification() must be called after setType(), because it adds to the type
     * @param sendnotification true or false
     */
    public void setSendNotification(final boolean sendnotification){
        final EndEntityType type = getType();
        if (sendnotification) {
            type.addType(EndEntityTypes.SENDNOTIFICATION);
        } else {
            type.removeType(EndEntityTypes.SENDNOTIFICATION);
        }
        setType(type);
    }

    public boolean getPrintUserData(){
        return getType().contains(EndEntityTypes.PRINT);
    }

    public void setPrintUserData(final boolean printUserData){
        final EndEntityType type = getType();
        if (printUserData) {
            type.addType(EndEntityTypes.PRINT);
        } else {
            type.removeType(EndEntityTypes.PRINT);
        }
        setType(type);
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
            try (final java.beans.XMLDecoder decoder = new java.beans.XMLDecoder(new ByteArrayInputStream(extendedinfostring.getBytes(StandardCharsets.UTF_8)));) {
            	final HashMap<?, ?> data = (HashMap<?, ?>) decoder.readObject();
            	// No need to b64 decode Integer value, just read it
            	final int type = ((Integer) data.get(ExtendedInformation.TYPE)).intValue();
            	switch (type) {
            	case ExtendedInformation.TYPE_BASIC :
            	    returnval = new ExtendedInformation();
            	    returnval.loadData(data);
            	    break;
            	}
            }
        }
        return returnval;
    }

    public static String extendedInformationToStringData(final ExtendedInformation extendedinformation) {
    	String ret = null;
    	if (extendedinformation != null){
            // We must base64 encode string for UTF safety
            final HashMap<Object, Object> b64DataMap = new Base64PutHashMap();
            b64DataMap.putAll(extendedinformation.getRawData());
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    		try (final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);) {
    		    encoder.writeObject(b64DataMap);
    		}
    		ret = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    	}
    	return ret;
    }

    /** @return the DN to be used when creating a certificate (without empty fields).
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
                    extendedInformationDump.append(", [" + (String) key + ":" + rawData.get(key).toString() + "]");
                }
            }
            extendedInformationDump.append("}");
            details.put("extendedInformation", extendedInformationDump.substring(2));
        }
        details.put("hardtokenissuerid", Integer.toString(hardtokenissuerid));
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
}
