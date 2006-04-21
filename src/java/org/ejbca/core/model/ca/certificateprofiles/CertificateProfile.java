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
 
package org.ejbca.core.model.ca.certificateprofiles;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ra.raadmin.DNFieldExtractor;


/**
 * CertificateProfile is a basic class used to customize a certificate
 * configuration or be inherited by fixed certificate profiles.
 *
 * @version $Id: CertificateProfile.java,v 1.4 2006-04-21 12:31:15 anatom Exp $
 */
public class CertificateProfile extends UpgradeableDataHashMap implements Serializable, Cloneable {
    private static final Logger log = Logger.getLogger(CertificateProfile.class);
    // Default Values
    public static final float LATEST_VERSION = (float) 16.0;

    /** KeyUsage constants */
    public static final int DIGITALSIGNATURE = 0;
    public static final int NONREPUDIATION   = 1;
    public static final int KEYENCIPHERMENT  = 2;
    public static final int DATAENCIPHERMENT = 3;
    public static final int KEYAGREEMENT     = 4;
    public static final int KEYCERTSIGN      = 5;
    public static final int CRLSIGN          = 6;
    public static final int ENCIPHERONLY     = 7;
    public static final int DECIPHERONLY     = 8;

    /** Extended key usage constants */
    public static final int ANYEXTENDEDKEYUSAGE = 0;
    public static final int SERVERAUTH          = 1;
    public static final int CLIENTAUTH          = 2;
    public static final int CODESIGNING         = 3;
    public static final int EMAILPROTECTION     = 4;
    public static final int IPSECENDSYSTEM      = 5;
    public static final int IPSECTUNNEL         = 6;
    public static final int IPSECUSER           = 7;
    public static final int TIMESTAMPING        = 8;
    public static final int SMARTCARDLOGON      = 9;
	public static final int OCSPSIGNING         = 10;
	
    public static final String[] EXTENDEDKEYUSAGEOIDSTRINGS = {"1.3.6.1.5.5.7.3.0", "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.4",
                                                              "1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6", "1.3.6.1.5.5.7.3.7", "1.3.6.1.5.5.7.3.8", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.9"};

	/** Microsoft Template Constants */
	public static final String MSTEMPL_DOMAINCONTROLLER  = "DomainController";
	
	public static final String[] AVAILABLE_MSTEMPLATES = {MSTEMPL_DOMAINCONTROLLER};
    
    public static final String TRUE  = "true";
    public static final String FALSE = "false";

    public static final int TYPE_ENDENTITY  = CertificateDataBean.CERTTYPE_ENDENTITY;
    public static final int TYPE_SUBCA      = CertificateDataBean.CERTTYPE_SUBCA;
    public static final int TYPE_ROOTCA     = CertificateDataBean.CERTTYPE_ROOTCA;
    public static final int NUMBER_OF_TYPES = 3;

    /** Supported certificate versions. */
    public static final String VERSION_X509V3 = "X509v3";
    public static final String CERTIFICATEPROFILENAME =  "CUSTOM";
    
    /** Constant indicating that any CA can be used with this certificate profile.*/
    public static final int ANYCA = -1;

    // protected fields.
    protected static final String CERTVERSION                    = "certversion";
    protected static final String VALIDITY                       = "validity";
    protected static final String USEBASICCONSTRAINTS            = "usebasicconstrants";
    protected static final String BASICCONSTRAINTSCRITICAL       = "basicconstraintscritical";
    protected static final String USEKEYUSAGE                    = "usekeyusage";
    protected static final String KEYUSAGECRITICAL               = "keyusagecritical";
    protected static final String USESUBJECTKEYIDENTIFIER        = "usesubjectkeyidentifier";
    protected static final String SUBJECTKEYIDENTIFIERCRITICAL   = "subjectkeyidentifiercritical";
    protected static final String USEAUTHORITYKEYIDENTIFIER      = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USECRLNUMBER                   = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL              = "crlnumbercritical";
    protected static final String USESUBJECTALTERNATIVENAME      = "usesubjectalternativename";
    protected static final String SUBJECTALTERNATIVENAMECRITICAL = "subjectalternativenamecritical";
    protected static final String USECRLDISTRIBUTIONPOINT        = "usecrldistributionpoint";
    protected static final String USEDEFAULTCRLDISTRIBUTIONPOINT = "usedefaultcrldistributionpoint";
    protected static final String CRLDISTRIBUTIONPOINTCRITICAL   = "crldistributionpointcritical";
    protected static final String CRLDISTRIBUTIONPOINTURI        = "crldistributionpointuri";
    protected static final String USECERTIFICATEPOLICIES         = "usecertificatepolicies";
    protected static final String CERTIFICATEPOLICIESCRITICAL    = "certificatepoliciescritical";
    protected static final String CERTIFICATEPOLICYID            = "certificatepolicyid";
    /** Policy Notice Url to CPS field alias in the data structure */
    protected static final String POLICY_NOTICE_CPS_URL 		 = "policynoticecpsurl";    
    /** Policy Notice User Notice field alias in the data structure */
    protected static final String POLICY_NOTICE_UNOTICE_TEXT 	 = "policynoticeunoticetext";
    protected static final String AVAILABLEBITLENGTHS            = "availablebitlengths";
    protected static final String KEYUSAGE                       = "keyusage";
    protected static final String MINIMUMAVAILABLEBITLENGTH      = "minimumavailablebitlength";
    protected static final String MAXIMUMAVAILABLEBITLENGTH      = "maximumavailablebitlength";
    public    static final String TYPE                           = "type";
    protected static final String ALLOWKEYUSAGEOVERRIDE          = "allowkeyusageoverride";
    protected static final String USEEXTENDEDKEYUSAGE            = "useextendedkeyusage";
    protected static final String EXTENDEDKEYUSAGE               = "extendedkeyusage";
    protected static final String EXTENDEDKEYUSAGECRITICAL       = "extendedkeyusagecritical";
    protected static final String AVAILABLECAS                   = "availablecas";
    protected static final String USEDPUBLISHERS                 = "usedpublishers";         
	protected static final String USEOCSPSERVICELOCATOR          = "useocspservicelocator";
	protected static final String USEDEFAULTOCSPSERVICELOCATOR   = "usedefaultocspservicelocator";	
	protected static final String OCSPSERVICELOCATORURI          = "ocspservicelocatoruri";
	protected static final String USEMICROSOFTTEMPLATE           = "usemicrosofttemplate";
	protected static final String MICROSOFTTEMPLATE              = "microsofttemplate";
	protected static final String USECNPOSTFIX                   = "usecnpostfix";
	protected static final String CNPOSTFIX                      = "cnpostfix";	
	protected static final String USESUBJECTDNSUBSET             = "usesubjectdnsubset";
	protected static final String SUBJECTDNSUBSET                = "subjectdnsubset";
	protected static final String USESUBJECTALTNAMESUBSET        = "usesubjectaltnamesubset";
	protected static final String SUBJECTALTNAMESUBSET           = "subjectaltnamesubset";
	protected static final String USEPATHLENGTHCONSTRAINT        = "usepathlengthconstraint";
	protected static final String PATHLENGTHCONSTRAINT           = "pathlengthconstraint";
    protected static final String USEQCSTATEMENT                 = "useqcstatement";
    protected static final String USEPKIXQCSYNTAXV2              = "usepkixqcsyntaxv2";
    protected static final String QCSTATEMENTCRITICAL            = "useqcstatementcritical";
    protected static final String QCSTATEMENTRANAME              = "useqcstatementraname";
    protected static final String QCSSEMANTICSID                 = "useqcsematicsid";
    protected static final String USEQCETSIQCCOMPLIANCE          = "useqcetsiqccompliance";
    protected static final String USEQCETSIVALUELIMIT            = "useqcetsivaluelimit";
    protected static final String QCETSIVALUELIMIT               = "qcetsivaluelimit";
    protected static final String QCETSIVALUELIMITEXP            = "qcetsivaluelimitexp";
    protected static final String QCETSIVALUELIMITCURRENCY       = "qcetsivaluelimitcurrency";
    protected static final String USEQCETSISIGNATUREDEVICE       = "useqcetsisignaturedevice";
    
     
    // Public Methods

    /**
     * Creates a new instance of CertificateProfile
     */
    public CertificateProfile() {
      setCertificateVersion(VERSION_X509V3);
      setValidity(730);

      setUseBasicConstraints(true);
      setBasicConstraintsCritical(true);

      setUseSubjectKeyIdentifier(true);
      setSubjectKeyIdentifierCritical(false);

      setUseAuthorityKeyIdentifier(true);
      setAuthorityKeyIdentifierCritical(false);

      setUseSubjectAlternativeName(true);
      setSubjectAlternativeNameCritical(false);

      setUseCRLDistributionPoint(false);
      setUseDefaultCRLDistributionPoint(false);
      setCRLDistributionPointCritical(false);
      setCRLDistributionPointURI("");

      setUseCertificatePolicies(false);
      setCertificatePoliciesCritical(false);
      setCertificatePolicyId("2.5.29.32.0");
      setCpsUrl("");
      setUserNoticeText("");

      setType(TYPE_ENDENTITY);

      int[] bitlengths = {512,1024,2048,4096};
      setAvailableBitLengths(bitlengths);

      setUseKeyUsage(true);
      setKeyUsage(new boolean[9]);
      setAllowKeyUsageOverride(true);
      setKeyUsageCritical(true);

      setUseExtendedKeyUsage(false);
      setExtendedKeyUsage(new ArrayList());
      setExtendedKeyUsageCritical(false);

      ArrayList availablecas = new ArrayList();
      availablecas.add(new Integer(ANYCA));
      setAvailableCAs(availablecas);
      
      setPublisherList(new ArrayList());
      
	  setUseOCSPServiceLocator(false);	  
	  setUseDefaultOCSPServiceLocator(false);
	  setOCSPServiceLocatorURI("");

	  setUseMicrosoftTemplate(false);	  
	  setMicrosoftTemplate("");
	  
	  setUseCNPostfix(false);
	  setCNPostfix("");
	  
	  setUseSubjectDNSubSet(false);
	  setSubjectDNSubSet(new ArrayList());
	  setUseSubjectAltNameSubSet(false);
	  setSubjectAltNameSubSet(new ArrayList());
	  
	  setUsePathLengthConstraint(false);
	  setPathLengthConstraint(0);
	  
      setUseQCStatement(false);
      setUsePkixQCSyntaxV2(false);
      setQCStatementCritical(false);
      setQCStatementRAName(null);
      setQCSemanticsId(null);
      setUseQCEtsiQCCompliance(false);
      setUseQCEtsiSignatureDevice(false);
      setUseQCEtsiValueLimit(false);
      setQCEtsiValueLimit(0);
      setQCEtsiValueLimitExp(0);
      setQCEtsiValueLimitCurrency(null);
    }



	// Public Methods.
    /** Returns the version of the certificate, should be one of the VERSION_ constants defined in CertificateProfile class. */
    public String getCertificateVersion(){return (String) data.get(CERTVERSION);}
	/**
	* Returns the version of the certificate, should be one of the VERSION_ constants defined in
	* CertificateProfile class.
	*
	* @return DOCUMENT ME!
	*/
    public void setCertificateVersion(String version){data.put(CERTVERSION,version);}

    public long getValidity(){return ((Long)data.get(VALIDITY)).longValue();}
    public void setValidity(long validity) { data.put(VALIDITY,new Long(validity));}

    public boolean getUseBasicConstraints(){ return ((Boolean)data.get(USEBASICCONSTRAINTS)).booleanValue(); }
    public void setUseBasicConstraints(boolean usebasicconstraints) {data.put(USEBASICCONSTRAINTS, Boolean.valueOf(usebasicconstraints));}

    public boolean getBasicConstraintsCritical(){ return ((Boolean) data.get(BASICCONSTRAINTSCRITICAL)).booleanValue(); }
    public void setBasicConstraintsCritical(boolean basicconstraintscritical) { data.put(BASICCONSTRAINTSCRITICAL, Boolean.valueOf(basicconstraintscritical));}

    public boolean getUseKeyUsage(){ return ((Boolean) data.get(USEKEYUSAGE)).booleanValue(); }
    public void setUseKeyUsage(boolean usekeyusage) { data.put(USEKEYUSAGE, Boolean.valueOf(usekeyusage));}

    public boolean getKeyUsageCritical(){ return ((Boolean) data.get(KEYUSAGECRITICAL)).booleanValue(); }
    public void setKeyUsageCritical(boolean keyusagecritical) { data.put(KEYUSAGECRITICAL, Boolean.valueOf(keyusagecritical));}

    public boolean getUseSubjectKeyIdentifier(){ return ((Boolean) data.get(USESUBJECTKEYIDENTIFIER)).booleanValue(); }
    public void setUseSubjectKeyIdentifier(boolean usesubjectkeyidentifier) { data.put(USESUBJECTKEYIDENTIFIER, Boolean.valueOf(usesubjectkeyidentifier));}

    public boolean getSubjectKeyIdentifierCritical(){ return ((Boolean) data.get(SUBJECTKEYIDENTIFIERCRITICAL)).booleanValue(); }
    public void setSubjectKeyIdentifierCritical(boolean subjectkeyidentifiercritical) { data.put(SUBJECTKEYIDENTIFIERCRITICAL, Boolean.valueOf(subjectkeyidentifiercritical));}

    public boolean getUseAuthorityKeyIdentifier(){ return ((Boolean) data.get(USEAUTHORITYKEYIDENTIFIER)).booleanValue(); }
    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) { data.put(USEAUTHORITYKEYIDENTIFIER, Boolean.valueOf(useauthoritykeyidentifier));}

    public boolean getAuthorityKeyIdentifierCritical(){ return ((Boolean) data.get(AUTHORITYKEYIDENTIFIERCRITICAL)).booleanValue(); }
    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) { data.put(AUTHORITYKEYIDENTIFIERCRITICAL, Boolean.valueOf(authoritykeyidentifiercritical));}

    public boolean getUseSubjectAlternativeName(){ return ((Boolean) data.get(USESUBJECTALTERNATIVENAME)).booleanValue(); }
    public void setUseSubjectAlternativeName(boolean usesubjectalternativename) { data.put(USESUBJECTALTERNATIVENAME, Boolean.valueOf(usesubjectalternativename));}

    public boolean getSubjectAlternativeNameCritical(){ return ((Boolean) data.get(SUBJECTALTERNATIVENAMECRITICAL)).booleanValue(); }
    public void setSubjectAlternativeNameCritical(boolean subjectalternativenamecritical) { data.put(SUBJECTALTERNATIVENAMECRITICAL, Boolean.valueOf(subjectalternativenamecritical));}

    public boolean getUseCRLDistributionPoint(){ return ((Boolean) data.get(USECRLDISTRIBUTIONPOINT)).booleanValue(); }
    public void setUseCRLDistributionPoint(boolean usecrldistributionpoint) { data.put(USECRLDISTRIBUTIONPOINT, Boolean.valueOf(usecrldistributionpoint));}

    public boolean getUseDefaultCRLDistributionPoint(){ return ((Boolean) data.get(USEDEFAULTCRLDISTRIBUTIONPOINT)).booleanValue(); }
    public void setUseDefaultCRLDistributionPoint(boolean usedefaultcrldistributionpoint) { data.put(USEDEFAULTCRLDISTRIBUTIONPOINT, Boolean.valueOf(usedefaultcrldistributionpoint));}
    
    public boolean getCRLDistributionPointCritical(){ return ((Boolean) data.get(CRLDISTRIBUTIONPOINTCRITICAL)).booleanValue(); }
    public void setCRLDistributionPointCritical(boolean crldistributionpointcritical) { data.put(CRLDISTRIBUTIONPOINTCRITICAL, Boolean.valueOf(crldistributionpointcritical));}

    public String getCRLDistributionPointURI(){ return (String) data.get(CRLDISTRIBUTIONPOINTURI); }
    public void setCRLDistributionPointURI(String crldistributionpointuri) {
      if(crldistributionpointuri==null)
        data.put(CRLDISTRIBUTIONPOINTURI,"");
      else
        data.put(CRLDISTRIBUTIONPOINTURI,crldistributionpointuri);
    }

    public boolean getUseCertificatePolicies() { return ((Boolean) data.get(USECERTIFICATEPOLICIES)).booleanValue(); }
    public void  setUseCertificatePolicies(boolean usecertificatepolicies) { data.put(USECERTIFICATEPOLICIES, Boolean.valueOf(usecertificatepolicies));}
    public boolean getCertificatePoliciesCritical() { return ((Boolean) data.get(CERTIFICATEPOLICIESCRITICAL)).booleanValue(); }
    public void  setCertificatePoliciesCritical(boolean certificatepoliciescritical) { data.put(CERTIFICATEPOLICIESCRITICAL, Boolean.valueOf(certificatepoliciescritical));}
    public String getCertificatePolicyId() { return (String) data.get(CERTIFICATEPOLICYID); }
    public void  setCertificatePolicyId(String policyid){
      if(policyid == null)
        data.put(CERTIFICATEPOLICYID,"");
      else
        data.put(CERTIFICATEPOLICYID,policyid);
    }
    public String getCpsUrl() {
        return (String) data.get(POLICY_NOTICE_CPS_URL);
    }
    public void setCpsUrl(String cpsUrl) {
        try {
            if (!StringUtils.isEmpty(cpsUrl)) {
                // Test that it is a valid url
                new URL(cpsUrl);  
                data.put(POLICY_NOTICE_CPS_URL, cpsUrl);
            } else {
                data.put(POLICY_NOTICE_CPS_URL, "");                
            }
        } catch (MalformedURLException muex) {
            log.error("CPS url has incorrect format.", muex);
        }
    }
    public String getUserNoticeText() {
        return (String) data.get(POLICY_NOTICE_UNOTICE_TEXT);
    }
    public void setUserNoticeText(String userNoticeText) {
        if(userNoticeText == null) {
            data.put(POLICY_NOTICE_UNOTICE_TEXT, "");             
        } else {
            data.put(POLICY_NOTICE_UNOTICE_TEXT, userNoticeText);            
        }
    }

    public int getType(){ return ((Integer) data.get(TYPE)).intValue(); }
    public void setType(int type){ data.put(TYPE, new Integer(type)); }
    public boolean isTypeCA() { return ((Integer) data.get(TYPE)).intValue() == TYPE_SUBCA; }
    public boolean isTypeRootCA() { return ((Integer) data.get(TYPE)).intValue() == TYPE_ROOTCA; }
    public boolean isTypeEndEntity() { return ((Integer) data.get(TYPE)).intValue() == TYPE_ENDENTITY; }

    public int[] getAvailableBitLengths(){
      ArrayList availablebitlengths = (ArrayList) data.get(AVAILABLEBITLENGTHS);
      int[] returnval = new int[availablebitlengths.size()];

      for(int i=0; i < availablebitlengths.size(); i++){
        returnval[i] = ((Integer) availablebitlengths.get(i)).intValue();
      }

      return returnval;
    }

    public void setAvailableBitLengths(int[] availablebitlengths){
      ArrayList availbitlengths = new ArrayList(availablebitlengths.length);

      int minimumavailablebitlength = 99999999;
      int maximumavailablebitlength = 0;

      for(int i=0;i< availablebitlengths.length;i++){
        if( availablebitlengths[i] > maximumavailablebitlength)
          maximumavailablebitlength = availablebitlengths[i];
        if( availablebitlengths[i] < minimumavailablebitlength)
          minimumavailablebitlength = availablebitlengths[i];

        availbitlengths.add(new Integer(availablebitlengths[i]));
      }
      data.put(AVAILABLEBITLENGTHS, availbitlengths);
      data.put(MINIMUMAVAILABLEBITLENGTH, new Integer(minimumavailablebitlength));
      data.put(MAXIMUMAVAILABLEBITLENGTH, new Integer(maximumavailablebitlength));
    }

    public int getMinimumAvailableBitLength(){return ((Integer) data.get(MINIMUMAVAILABLEBITLENGTH)).intValue();}
    public int getMaximumAvailableBitLength(){return ((Integer) data.get(MAXIMUMAVAILABLEBITLENGTH)).intValue();}

    public boolean[] getKeyUsage(){
      ArrayList keyusage = (ArrayList) data.get(KEYUSAGE);
      boolean[] returnval = new boolean[keyusage.size()];

      for(int i=0; i < keyusage.size(); i++){
        returnval[i] = ((Boolean) keyusage.get(i)).booleanValue();
      }

      return returnval;
    }

    public boolean getKeyUsage(int keyusageconstant){
      return ((Boolean) ((ArrayList) data.get(KEYUSAGE)).get(keyusageconstant)).booleanValue();
    }

    public void setKeyUsage(boolean[] keyusage){
      ArrayList keyuse = new ArrayList(keyusage.length);

      for(int i=0;i< keyusage.length;i++){
        keyuse.add(Boolean.valueOf(keyusage[i]));
      }
      data.put(KEYUSAGE, keyuse);
    }

    public void setKeyUsage(int keyusageconstant, boolean value){
      ((ArrayList) data.get(KEYUSAGE)).set(keyusageconstant, Boolean.valueOf(value));
    }

    public void setAllowKeyUsageOverride(boolean override) {
        data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.valueOf(override));
    }
    public boolean getAllowKeyUsageOverride() {
        return ((Boolean) data.get(ALLOWKEYUSAGEOVERRIDE)).booleanValue();
    }

    public void setUseExtendedKeyUsage(boolean use) {
        data.put(USEEXTENDEDKEYUSAGE, Boolean.valueOf(use));
    }
    public boolean getUseExtendedKeyUsage() {
        return ((Boolean) data.get(USEEXTENDEDKEYUSAGE)).booleanValue();
    }

    public void setExtendedKeyUsageCritical(boolean critical) {
        data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.valueOf(critical));
    }
    public boolean getExtendedKeyUsageCritical() {
        return ((Boolean) data.get(EXTENDEDKEYUSAGECRITICAL)).booleanValue();
    }
    /**
     * Extended Key Usage is an arraylist of constant Integers.
     */
    public void setExtendedKeyUsage(ArrayList extendedkeyusage) {
        data.put(EXTENDEDKEYUSAGE, extendedkeyusage);
    }
    /**
     * Extended Key Usage is an arraylist of constant Integers.
     */
    public ArrayList getExtendedKeyUsage() {
        return (ArrayList) data.get(EXTENDEDKEYUSAGE);
    }

    public boolean getUseMicrosoftTemplate(){
    	return ((Boolean) data.get(USEMICROSOFTTEMPLATE)).booleanValue();	
    }
    
    public void setUseMicrosoftTemplate(boolean use){
    	data.put(USEMICROSOFTTEMPLATE, Boolean.valueOf(use));	
    }

    public String getMicrosoftTemplate(){
    	return (String) data.get(MICROSOFTTEMPLATE);	
    }
    
    public void setMicrosoftTemplate(String mstemplate){
    	data.put(MICROSOFTTEMPLATE, mstemplate);	
    }
    
    public boolean getUseCNPostfix(){
    	return ((Boolean) data.get(USECNPOSTFIX)).booleanValue();	
    }
    
    public void setUseCNPostfix(boolean use) {
		data.put(USECNPOSTFIX, Boolean.valueOf(use));			
	}
    
    public String getCNPostfix(){
    	return (String) data.get(CNPOSTFIX);	
    }
    
    public void setCNPostfix(String cnpostfix) {
		data.put(CNPOSTFIX, cnpostfix);	
		
	}
	
    public boolean getUseSubjectDNSubSet(){
    	return ((Boolean) data.get(USESUBJECTDNSUBSET)).booleanValue();	
    }
    
    public void setUseSubjectDNSubSet(boolean use) {
		data.put(USESUBJECTDNSUBSET, Boolean.valueOf(use));			
	}
    
    /**
     * Returns a collection of Integer (DNFieldExtractor constants) indicating
     * which subject dn fields that should be used in certificate.
     * 
     */
    public Collection getSubjectDNSubSet(){
    	return (Collection) data.get(SUBJECTDNSUBSET);	
    }

    /**
     * Should contain a collection of Integer (DNFieldExtractor constants) indicating
     * which subject dn fields that should be used in certificate.
     * 
     */
    public void setSubjectDNSubSet(Collection subjectdns) {
		data.put(SUBJECTDNSUBSET, subjectdns);	
		
	}

    /**
     * Method taking a full user dn and returns a DN only containing the 
     * DN fields specified in the subjectdn sub set array.
     * 
     * @param dn
     * @return a subset of original DN
     */
    
    public String createSubjectDNSubSet(String dn){
    	DNFieldExtractor extractor = new DNFieldExtractor(dn,DNFieldExtractor.TYPE_SUBJECTDN);    	
    	return constructUserData(extractor, getSubjectDNSubSet(), true);
    }
    
    public boolean getUseSubjectAltNameSubSet(){
    	return ((Boolean) data.get(USESUBJECTALTNAMESUBSET)).booleanValue();	
    }
    
    public void setUseSubjectAltNameSubSet(boolean use) {
		data.put(USESUBJECTALTNAMESUBSET, Boolean.valueOf(use));			
	}

    /**
     * Returns a collection of Integer (DNFieldExtractor constants) indicating
     * which subject altnames fields that should be used in certificate.
     * 
     */
    public Collection getSubjectAltNameSubSet(){
    	return (Collection) data.get(SUBJECTALTNAMESUBSET);	
    }
    
    /**
     * Returns a collection of Integer (DNFieldExtractor constants) indicating
     * which subject altnames fields that should be used in certificate.
     * 
     */
    public void setSubjectAltNameSubSet(Collection subjectaltnames) {
		data.put(SUBJECTALTNAMESUBSET, subjectaltnames);	
		
	}

    
    /**
     * Method taking a full user dn and returns a AltName only containing the 
     * AltName fields specified in the subjectaltname sub set array.
     * 
     * @param dn
     * @return a subset of original DN
     */
    public String createSubjectAltNameSubSet(String subjectaltname){
    	DNFieldExtractor extractor = new DNFieldExtractor(subjectaltname,DNFieldExtractor.TYPE_SUBJECTALTNAME);    	
    	return constructUserData(extractor, getSubjectAltNameSubSet(), false);
    }
    
    /**
     * Help method converting a full DN or Subject Alt Name to one usng only specified fields
     * @param extractor 
     * @param usefields
     * @return
     */
    protected String constructUserData(DNFieldExtractor extractor, Collection usefields, boolean subjectdn){
        String retval = "";
                       
        if(usefields instanceof List){
          Collections.sort((List) usefields);
        }
        Iterator iter = usefields.iterator(); 
        String dnField = null;
        while(iter.hasNext()){
        	Integer next = (Integer) iter.next();
        	dnField = getDNField(extractor, next.intValue(), subjectdn);
        	if (StringUtils.isNotEmpty(dnField)) {
            	if(retval.length() == 0)
              	  retval += dnField; // first item, don't start with a comma
              	else
              	  retval += "," + dnField;      	    
        	}
        }
        
              
        log.debug("CertificateProfile: constructed DN or AltName: " + retval );
        return retval;	
      }
      
      protected String getDNField(DNFieldExtractor extractor, int field, boolean subjectdn){
        String retval = "";
        String[] fieldnames =  DNFieldExtractor.SUBJECTDNFIELDS;
        int f = field;
        if(!subjectdn){
        	fieldnames =  DNFieldExtractor.SUBJECTALTNAME;
        	f = field - DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY;
        }
        
        int num = extractor.getNumberOfFields(field);
        for(int i=0;i<num;i++){
        	if(retval.length() == 0)
        	  retval += fieldnames[f] + extractor.getField(field,i);
        	else
        	  retval += "," + fieldnames[f] + extractor.getField(field,i);	
        }    
        return retval;      	
      }
    
    
    /**
     * Returns an ArrayList of OID.strings defined in constant EXTENDEDKEYUSAGEOIDSTRINGS.
     */
    public ArrayList getExtendedKeyUsageAsOIDStrings(){
      ArrayList returnval = new ArrayList();
      ArrayList eku = (ArrayList) data.get(EXTENDEDKEYUSAGE);
      Iterator i = eku.iterator();
      while(i.hasNext())
        returnval.add(EXTENDEDKEYUSAGEOIDSTRINGS[((Integer) i.next()).intValue()]);


      return returnval;
    }
    
    /**
     * Returns a Collections of caids (Integer), indicating which CAs the profile should
     * be applicable to.
     *
     * If it contains the constant ANYCA then the profile is applicable to all CAs
     */
    public Collection getAvailableCAs(){
      return (Collection) data.get(AVAILABLECAS);   
    }
    
    /**
     * Saves the CertificateProfile's list of CAs the cert profile is applicable to.
     *
     * @param availablecas a Collection of caids (Integer)
     */
    
    public void setAvailableCAs(Collection availablecas){
      data.put(AVAILABLECAS, availablecas);   
    }
    
    public boolean isApplicableToAnyCA(){
    	return ((Collection) data.get(AVAILABLECAS)).contains(new Integer(ANYCA));
    }
    
    /**
     * Returns a Collection of publisher id's (Integer) indicating which publishers a certificate
     * created with this profile should be published to.
     */
    
    public Collection getPublisherList(){
      return (Collection) data.get(USEDPUBLISHERS);  
    }
    
    /**
     * Saves the CertificateProfile's list of publishers that certificates created with this profile 
     * should be published to.
     *
     * @param publishers a Collection of publisherids (Integer)
     */ 
    
    public void setPublisherList(Collection publisher){
      data.put(USEDPUBLISHERS, publisher);   
    }   
    	
    /**
     * Method indicating that Path Length Constain should be used in the BasicConstaint
     * 
     */
    public boolean getUsePathLengthConstraint(){
    	return ((Boolean) data.get(USEPATHLENGTHCONSTRAINT)).booleanValue();	
    }
    
    /**
     * Method indicating that Path Length Constain should be used in the BasicConstaint
     * 
     */
    public void setUsePathLengthConstraint(boolean use) {
		data.put(USEPATHLENGTHCONSTRAINT, Boolean.valueOf(use));			
	}
    
    public int getPathLengthConstraint(){
    	return ((Integer) data.get(PATHLENGTHCONSTRAINT)).intValue();	
    }
    
  
    public void setPathLengthConstraint(int pathlength) {
		data.put(PATHLENGTHCONSTRAINT, new Integer(pathlength));			
	}   

	public boolean getUseOCSPServiceLocator(){ return ((Boolean) data.get(USEOCSPSERVICELOCATOR)).booleanValue(); }
	public void setUseOCSPServiceLocator(boolean useocspservicelocator) { data.put(USEOCSPSERVICELOCATOR, Boolean.valueOf(useocspservicelocator));}
    
	public boolean getUseDefaultOCSPServiceLocator(){ return ((Boolean) data.get(USEDEFAULTOCSPSERVICELOCATOR)).booleanValue(); }
	public void setUseDefaultOCSPServiceLocator(boolean usedefaultocspservicelocator) { data.put(USEDEFAULTOCSPSERVICELOCATOR, Boolean.valueOf(usedefaultocspservicelocator));}

	public String getOCSPServiceLocatorURI(){ return (String) data.get(OCSPSERVICELOCATORURI); }
	public void setOCSPServiceLocatorURI(String ocspservicelocatoruri) {
	  if(ocspservicelocatoruri==null)
		data.put(OCSPSERVICELOCATORURI,"");
	  else
		data.put(OCSPSERVICELOCATORURI,ocspservicelocatoruri);
	}

    public boolean getUseQCStatement(){ return ((Boolean) data.get(USEQCSTATEMENT)).booleanValue(); }
    public void setUseQCStatement(boolean useqcstatement) { data.put(USEQCSTATEMENT, Boolean.valueOf(useqcstatement));}
    public boolean getUsePkixQCSyntaxV2(){ return ((Boolean) data.get(USEPKIXQCSYNTAXV2)).booleanValue(); }
    public void setUsePkixQCSyntaxV2(boolean pkixqcsyntaxv2) { data.put(USEPKIXQCSYNTAXV2, Boolean.valueOf(pkixqcsyntaxv2));}
    public boolean getQCStatementCritical() { return ((Boolean) data.get(QCSTATEMENTCRITICAL)).booleanValue(); }
    public void  setQCStatementCritical(boolean qcstatementcritical) { data.put(QCSTATEMENTCRITICAL, Boolean.valueOf(qcstatementcritical));}

    public String getQCStatementRAName(){ return (String) data.get(QCSTATEMENTRANAME); }
    public void setQCStatementRAName(String qcstatementraname) {
      if(qcstatementraname==null)
        data.put(QCSTATEMENTRANAME,"");
      else
        data.put(QCSTATEMENTRANAME,qcstatementraname);
    }
    public String getQCSemanticsId(){ return (String) data.get(QCSSEMANTICSID); }
    public void setQCSemanticsId(String qcsemanticsid) {
      if(qcsemanticsid==null)
        data.put(QCSSEMANTICSID,"");
      else
        data.put(QCSSEMANTICSID,qcsemanticsid);
    }
    public boolean getUseQCEtsiQCCompliance(){ return ((Boolean) data.get(USEQCETSIQCCOMPLIANCE)).booleanValue(); }
    public void setUseQCEtsiQCCompliance(boolean useqcetsiqccompliance) { data.put(USEQCETSIQCCOMPLIANCE, Boolean.valueOf(useqcetsiqccompliance));}
    public boolean getUseQCEtsiValueLimit(){ return ((Boolean) data.get(USEQCETSIVALUELIMIT)).booleanValue(); }
    public void setUseQCEtsiValueLimit(boolean useqcetsivaluelimit) { data.put(USEQCETSIVALUELIMIT, Boolean.valueOf(useqcetsivaluelimit));}
    public int getQCEtsiValueLimit(){return ((Integer) data.get(QCETSIVALUELIMIT)).intValue();}
    public void setQCEtsiValueLimit(int qcetsivaluelimit){data.put(QCETSIVALUELIMIT, new Integer(qcetsivaluelimit));}
    public int getQCEtsiValueLimitExp(){return ((Integer) data.get(QCETSIVALUELIMITEXP)).intValue();}
    public void setQCEtsiValueLimitExp(int qcetsivaluelimitexp){data.put(QCETSIVALUELIMITEXP, new Integer(qcetsivaluelimitexp));}
    public String getQCEtsiValueLimitCurrency(){ return (String) data.get(QCETSIVALUELIMITCURRENCY); }
    public void setQCEtsiValueLimitCurrency(String qcetsicaluelimitcurrency) {
      if(qcetsicaluelimitcurrency==null)
        data.put(QCETSIVALUELIMITCURRENCY,"");
      else
        data.put(QCETSIVALUELIMITCURRENCY,qcetsicaluelimitcurrency);
    }
    public boolean getUseQCEtsiSignatureDevice(){ return ((Boolean) data.get(USEQCETSISIGNATUREDEVICE)).booleanValue(); }
    public void setUseQCEtsiSignatureDevice(boolean useqcetsisignaturedevice) { data.put(USEQCETSISIGNATUREDEVICE, Boolean.valueOf(useqcetsisignaturedevice));}
    
    public Object clone() throws CloneNotSupportedException {
      CertificateProfile clone = new CertificateProfile();
      HashMap clonedata = (HashMap) clone.saveData();

      Iterator i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();
        clonedata.put(key, data.get(key));
      }

      clone.loadData(clonedata);
      return clone;
    }

    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** 
     * Implemtation of UpgradableDataHashMap function upgrade. 
     */
    public void upgrade(){
        log.debug(">upgrade");
        if(LATEST_VERSION != getVersion()){
            // New version of the class, upgrade
            log.info("upgrading certificateprofile with version "+getVersion());

            data.put(VERSION, new Float(LATEST_VERSION));
            if(data.get(ALLOWKEYUSAGEOVERRIDE) == null)
                data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
            if(data.get(USEEXTENDEDKEYUSAGE) ==null)
                data.put(USEEXTENDEDKEYUSAGE, Boolean.FALSE);
            if(data.get(EXTENDEDKEYUSAGE) ==null)
                data.put(EXTENDEDKEYUSAGE, new ArrayList());
            if(data.get(EXTENDEDKEYUSAGECRITICAL) == null)
                data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.FALSE);
            if(data.get(AVAILABLECAS) == null){
                ArrayList availablecas = new ArrayList();
                availablecas.add(new Integer(ANYCA));
                data.put(AVAILABLECAS, availablecas);
            }
            if(data.get(USEDPUBLISHERS) == null){
                data.put(USEDPUBLISHERS, new ArrayList());   
            }            
            if(data.get(USEOCSPSERVICELOCATOR) == null){
                setUseOCSPServiceLocator(false);            
                setOCSPServiceLocatorURI("");
            }
            
            if(data.get(USEMICROSOFTTEMPLATE) == null){
                setUseMicrosoftTemplate(false);            
                setMicrosoftTemplate("");
            } 
            
            if(data.get(USECNPOSTFIX) == null){
          	  setUseCNPostfix(false);
        	  setCNPostfix("");
            } 
            
            if(data.get(USESUBJECTDNSUBSET) == null){
          	  setUseSubjectDNSubSet(false);
        	  setSubjectDNSubSet(new ArrayList());
        	  setUseSubjectAltNameSubSet(false);
        	  setSubjectAltNameSubSet(new ArrayList());
            }
            
            if(data.get(USEPATHLENGTHCONSTRAINT) == null){
            	setUsePathLengthConstraint(false);
            	setPathLengthConstraint(0);
            }
            
            if(data.get(USEQCSTATEMENT) == null){
                setUseQCStatement(false);
                setUsePkixQCSyntaxV2(false);
                setQCStatementCritical(false);
                setQCStatementRAName(null);
                setQCSemanticsId(null);
                setUseQCEtsiQCCompliance(false);
                setUseQCEtsiSignatureDevice(false);
                setUseQCEtsiValueLimit(false);
                setQCEtsiValueLimit(0);
                setQCEtsiValueLimitExp(0);
                setQCEtsiValueLimitCurrency(null);
            }
            
            if(data.get(USEDEFAULTCRLDISTRIBUTIONPOINT) == null){
            	setUseDefaultCRLDistributionPoint(false);
            	setUseDefaultOCSPServiceLocator(false);
            }
            
            if (data.get(POLICY_NOTICE_UNOTICE_TEXT) == null) {
                setUserNoticeText(null); // This actually isn't nessecary but for the principle we do it
            }
            if (data.get(POLICY_NOTICE_CPS_URL) == null) {
                setCpsUrl(null); // This actually isn't nessecary but for the principle we do it
            }
            
        }
        log.debug("<upgrade");
    }
    
}