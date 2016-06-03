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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
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
    private ExtendedInformation extendedinformation;
    private String keyStoreAlgorithm;
    private String keyStoreAlgorithmLength;

    /** Creates new empty EndEntityInformation */
    public EndEntityInformation() {
    }

    /**
     * Creates new EndEntityInformation. All fields are almost required in this constructor. Password must
     * be set manually though. This is so you should be sure what you do with the password.
     *
     * @param user DOCUMENT ME!
     * @param dn DOCUMENT ME!
     * @param caid CA id of the CA that the user is registered with
     * @param subjectaltname DOCUMENT ME!
     * @param email DOCUMENT ME!
     * @param status Status of user, from {@link EndEntityConstants#STATUS_NEW} etc
     * @param type Type of user, from {@link EndEntityConstants#ENDUSER} etc, can be "ored" together, i.e. EndEntityConstants#USER_ENDUSER | {@link EndEntityConstants#SENDNOTIFICATION}
     * @param endentityprofileid DOCUMENT ME!
     * @param certificateprofileid DOCUMENT ME!
     * @param timecreated DOCUMENT ME!
     * @param timemodified DOCUMENT ME!
     * @param tokentype Type of token, from {@link EndEntityConstants#TOKEN_USERGEN} etc
     * @param hardtokenissuerid DOCUMENT ME!

     */
    public EndEntityInformation(String user, String dn, int caid, String subjectaltname, String email, int status, EndEntityType type, int endentityprofileid, int certificateprofileid,
                         Date timecreated, Date timemodified, int tokentype, int hardtokenissuerid, ExtendedInformation extendedinfo) {
        setUsername(user);
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
        setExtendedinformation(extendedinfo);
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
     * @param tokentype the type of token to be generated, one of SecConst.TOKEN constants
     * @param hardtokenissuerid if token should be hard, the id of the hard token issuer, else 0.
     * @param extendedinfo
     */
    public EndEntityInformation(String username, String dn, int caid, String subjectaltname, String email, EndEntityType type, int endentityprofileid, int certificateprofileid,
                          int tokentype, int hardtokenissuerid, ExtendedInformation extendedinfo) {
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
        setExtendedinformation(extendedinfo);
        setCardNumber(null);
        setKeyStoreAlgorithm(null);
        setKeyStoreAlgorithmLength(null);
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
     * @return keystore algorithm (DSA, ECDSA or RSA) for keystore tokens (P12 and JKS)
     */
    public String getKeyStoreAlgorithm(){return this.keyStoreAlgorithm;}
    /**
     * @param keyAlgorithm keystore algorithm ('DSA', 'ECDSA' or 'RSA') for keystore tokens (P12 and JKS)
     */
    public void setKeyStoreAlgorithm(String keyAlgorithm){this.keyStoreAlgorithm = keyAlgorithm;}
    /**
     * @return keystore algorithm length for non-EC or curve name for EC(etc. '1024', '2048,.. or 'brainpoolP224r1', 'prime239v1', 'secp256k1',..)
     */
    public String getKeyStoreAlgorithmLength(){return this.keyStoreAlgorithmLength;}
    /**
     * @param keyLength keystore algorithm length for non-EC or curve name for EC(etc. '1024', '2048,.. or 'brainpoolP224r1', 'prime239v1', 'secp256k1',..)
     */
    public void setKeyStoreAlgorithmLength(String keyLength){this.keyStoreAlgorithmLength = keyLength;}
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
    public boolean getAdministrator(){
      return getType().contains(EndEntityTypes.ADMINISTRATOR);
    }

    /**
     * @deprecated from EJBCA 3.8.0. The admin property is no longer used. This method is still used for deserializing objects in CertReqHistoryDataBean. 
     */
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
	public ExtendedInformation getExtendedinformation() {
		return extendedinformation;
	}
	/**
	 * @param extendedinformation The extendedinformation to set.
	 */
	public void setExtendedinformation(ExtendedInformation extendedinformation) {
		this.extendedinformation = extendedinformation;
	}
	
	
    /**
     * Help Method used to create an ExtendedInformation from String representation.
     * Used when creating an ExtendedInformation from queries.
     */
    public static ExtendedInformation getExtendedInformation(String extendedinfostring) {
        ExtendedInformation returnval = null;
        if ( (extendedinfostring != null) && (extendedinfostring.length() > 0) ) {
            try {
            	java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(extendedinfostring.getBytes("UTF8")));            	
            	HashMap<?, ?> h = (HashMap<?, ?>) decoder.readObject();
            	decoder.close();
                // Handle Base64 encoded string values
                HashMap<?, ?> data = new Base64GetHashMap(h);
            	int type = ((Integer) data.get(ExtendedInformation.TYPE)).intValue();
            	switch(type){
            	  case ExtendedInformation.TYPE_BASIC :
              		returnval = new ExtendedInformation();            	
              		returnval.loadData(data);
              		break;
            	}            	
            }catch (Exception e) {
            	throw new RuntimeException("Problems generating extended information from String",e);
            }
        }
        return returnval;
    }
    
    @SuppressWarnings("unchecked")
    public static String extendedInformationToStringData(ExtendedInformation extendedinformation) throws UnsupportedEncodingException {
    	String ret = null;
    	if(extendedinformation != null){
            // We must base64 encode string for UTF safety
            HashMap<Object, Object> a = new Base64PutHashMap();
            a.putAll((Map<Object, Object>)extendedinformation.saveData());
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    		encoder.writeObject(a);
    		encoder.close();
    		ret = baos.toString("UTF8");
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
    
    public String getTokenTypeName() {
        switch (getTokenType()) {
        case EndEntityConstants.TOKEN_SOFT_P12:
            return "P12";
        case EndEntityConstants.TOKEN_SOFT_JKS:
            return "JKS";
        case EndEntityConstants.TOKEN_SOFT_PEM:
            return "PEM";
        case EndEntityConstants.TOKEN_USERGEN:
            return "User Generated";
        case EndEntityConstants.TOKEN_SOFT:
            return "Soft";
        default:
            return "Unknown token type with id = '" + getTokenType() + "'";
        }
    }
}
