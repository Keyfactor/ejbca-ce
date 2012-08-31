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
package org.cesecore.certificates.ca;

import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;


/**
 * Holds non-sensitive information about a X509CA.
 *
 * Based on EJBCA version: X509CAInfo.java 11009 2010-12-29 15:20:37Z jeklund
 * 
 * @version $Id$
 */
public class X509CAInfo extends CAInfo{
   
	private static final long serialVersionUID = 1349353519030677161L;
	private List<CertificatePolicy> policies;
	private boolean useauthoritykeyidentifier;
	private boolean authoritykeyidentifiercritical;
	private boolean usecrlnumber;
	private boolean crlnumbercritical;
	private String defaultcrldistpoint;
	private String defaultcrlissuer;
	private String defaultocsplocator;
	private String cadefinedfreshestcrl;
	private String subjectaltname;
	private boolean useUTF8PolicyText;
	private boolean usePrintableStringSubjectDN;
	private boolean useLdapDNOrder;
	private boolean useCrlDistributionPointOnCrl;
	private boolean crlDistributionPointOnCrlCritical;
	private String cmpRaAuthSecret;
	private List<String> authorityInformationAccess;
    
    /**
     * Constructor that should be used when creating CA and retrieving CA info.
     */
    public X509CAInfo(final String subjectdn,final  String name, final int status, final Date updateTime, 
    		final String subjectaltname, final int certificateprofileid, final long validity, final Date expiretime, 
    		final int catype, final int signedby, final Collection<Certificate> certificatechain, final CATokenInfo catokeninfo, 
    		final String description, final int revocationReason, final Date revocationDate, final List<CertificatePolicy> policies,
    		final long crlperiod, final long crlIssueInterval, final long crlOverlapTime, final long deltacrlperiod, 
    		final Collection<Integer> crlpublishers, final boolean useauthoritykeyidentifier, final boolean authoritykeyidentifiercritical, 
    		final boolean usecrlnumber, final boolean crlnumbercritical, final String defaultcrldistpoint, final String defaultcrlissuer,  
    		final String defaultocspservicelocator, final List<String> authorityInformationAccess, final String cadefinedfreshestcrl, 
    		final boolean finishuser, final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos, 
    		final boolean useUTF8PolicyText, final Collection<Integer> approvalSettings, final int numOfReqApprovals, final boolean usePrintableStringSubjectDN, 
    		final boolean useLdapDnOrder, final boolean useCrlDistributionPointOnCrl, final boolean crlDistributionPointOnCrlCritical, final boolean includeInHealthCheck,
    		final boolean _doEnforceUniquePublicKeys, final boolean _doEnforceUniqueDistinguishedName, final boolean _doEnforceUniqueSubjectDNSerialnumber,
    		final boolean _useCertReqHistory, final boolean _useUserStorage, final boolean _useCertificateStorage, final String _cmpRaAuthSecret) {
        this.subjectdn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
        this.caid = this.subjectdn.hashCode();
        this.name = name;
        this.status = status;
        this.updatetime = updateTime;
        this.validity = validity;
        this.expiretime = expiretime;
        this.catype = catype;
        this.signedby = signedby;
        // Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure all certificates in this 
        // Array were of SUNs own provider, using CertTools.SYSTEM_SECURITY_PROVIDER.
        // As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1 anymore.
		try {
			if (certificatechain != null) {
		        X509Certificate[] certs = (X509Certificate[])certificatechain.toArray(new X509Certificate[certificatechain.size()]);
		        Collection<Certificate> list = CertTools.getCertCollectionFromArray(certs, null);
		        this.certificatechain = list;        				
			} else {
				this.certificatechain = null;
			}
		} catch (CertificateException e) {
			throw new IllegalArgumentException(e);
		} catch (NoSuchProviderException e) {
			throw new IllegalArgumentException(e);
		}
        this.catokeninfo = catokeninfo; 
        this.description = description;
        this.revocationReason = revocationReason;
        this.revocationDate = revocationDate;
        this.policies = policies;
        this.crlperiod = crlperiod;
        this.crlIssueInterval = crlIssueInterval;
        this.crlOverlapTime = crlOverlapTime;
        this.deltacrlperiod = deltacrlperiod;
        this.crlpublishers = crlpublishers;
        this.useauthoritykeyidentifier = useauthoritykeyidentifier;
        this.authoritykeyidentifiercritical = authoritykeyidentifiercritical;
        this.usecrlnumber = usecrlnumber;
        this.crlnumbercritical = crlnumbercritical;
        this.defaultcrldistpoint = defaultcrldistpoint;
        this.defaultcrlissuer = defaultcrlissuer;
        this.defaultocsplocator = defaultocspservicelocator;
        this.cadefinedfreshestcrl = cadefinedfreshestcrl;
        this.finishuser = finishuser;                     
        this.subjectaltname = subjectaltname;
        this.certificateprofileid = certificateprofileid;
        this.extendedcaserviceinfos = extendedcaserviceinfos; 
        this.useUTF8PolicyText = useUTF8PolicyText;
        this.approvalSettings = approvalSettings;
        this.numOfReqApprovals = numOfReqApprovals;
        this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
        this.useLdapDNOrder = useLdapDnOrder;
        this.useCrlDistributionPointOnCrl = useCrlDistributionPointOnCrl;
        this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
        this.includeInHealthCheck = includeInHealthCheck;
        this.doEnforceUniquePublicKeys = _doEnforceUniquePublicKeys;
        this.doEnforceUniqueDistinguishedName = _doEnforceUniqueDistinguishedName;
        this.doEnforceUniqueSubjectDNSerialnumber = _doEnforceUniqueSubjectDNSerialnumber;
        this.useCertReqHistory = _useCertReqHistory;
        this.useUserStorage = _useUserStorage;
        this.useCertificateStorage = _useCertificateStorage;
        this.cmpRaAuthSecret = _cmpRaAuthSecret;
        this.authorityInformationAccess = authorityInformationAccess;
        
    }

    /**
     * Constructor that should be used when updating CA data.
     * Used by the web. Jsp and stuff like that.
     */
    public X509CAInfo(final int caid, final long validity, final CATokenInfo catokeninfo, final String description,
    		final long crlperiod, final long crlIssueInterval, final long crlOverlapTime, final long deltacrlperiod, 
    		final Collection<Integer> crlpublishers, final boolean useauthoritykeyidentifier, final boolean authoritykeyidentifiercritical,
    		final boolean usecrlnumber, final boolean crlnumbercritical, final String defaultcrldistpoint, final String defaultcrlissuer, 
    		final String defaultocspservicelocator, final List<String> authorityInformationAccess,final String cadefinedfreshestcrl, 
    		final boolean finishuser, final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos, 
    		final boolean useUTF8PolicyText, final Collection<Integer> approvalSettings, final int numOfReqApprovals, final boolean usePrintableStringSubjectDN, 
    		final boolean useLdapDnOrder, final boolean useCrlDistributionPointOnCrl, final boolean crlDistributionPointOnCrlCritical, final boolean includeInHealthCheck,
    		final boolean _doEnforceUniquePublicKeys, final boolean _doEnforceUniqueDistinguishedName, final boolean _doEnforceUniqueSubjectDNSerialnumber, final boolean _useCertReqHistory, 
    		final boolean _useUserStorage, final boolean _useCertificateStorage, final String _cmpRaAuthSecret) {        
        this.caid = caid;
        this.validity=validity;
        this.catokeninfo = catokeninfo; 
        this.description = description;        
        this.crlperiod = crlperiod;
        this.crlIssueInterval = crlIssueInterval;
        this.crlOverlapTime = crlOverlapTime;
        this.deltacrlperiod = deltacrlperiod;
        this.crlpublishers = crlpublishers;
        this.useauthoritykeyidentifier = useauthoritykeyidentifier;
        this.authoritykeyidentifiercritical = authoritykeyidentifiercritical;
        this.usecrlnumber = usecrlnumber;
        this.crlnumbercritical = crlnumbercritical;
        this.defaultcrldistpoint = defaultcrldistpoint;
        this.defaultcrlissuer = defaultcrlissuer;
        this.defaultocsplocator = defaultocspservicelocator;
        this.cadefinedfreshestcrl = cadefinedfreshestcrl;
        this.finishuser = finishuser;
		this.extendedcaserviceinfos = extendedcaserviceinfos; 
        this.useUTF8PolicyText = useUTF8PolicyText;
        this.approvalSettings = approvalSettings;
        this.numOfReqApprovals = numOfReqApprovals;
        this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
        this.useLdapDNOrder = useLdapDnOrder;
        this.useCrlDistributionPointOnCrl = useCrlDistributionPointOnCrl;
        this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
        this.includeInHealthCheck = includeInHealthCheck;
        this.doEnforceUniquePublicKeys = _doEnforceUniquePublicKeys;
        this.doEnforceUniqueDistinguishedName = _doEnforceUniqueDistinguishedName;
        this.doEnforceUniqueSubjectDNSerialnumber = _doEnforceUniqueSubjectDNSerialnumber;
        this.useCertReqHistory = _useCertReqHistory;
        this.useUserStorage = _useUserStorage;
        this.useCertificateStorage = _useCertificateStorage;
        this.cmpRaAuthSecret = _cmpRaAuthSecret;
        this.authorityInformationAccess = authorityInformationAccess;
    }
  
  
  public X509CAInfo(){}
    
  public List<CertificatePolicy> getPolicies() {
	  return this.policies;
  }
  public void setPolicies(final List<CertificatePolicy> policies) {
      this.policies = policies;
  }
  public boolean getUseCRLNumber(){ return usecrlnumber;}
  public void setUseCRLNumber(boolean usecrlnumber){ this.usecrlnumber=usecrlnumber;}
  
  public boolean getCRLNumberCritical(){ return crlnumbercritical;}
  public void setCRLNumberCritical(boolean crlnumbercritical){ this.crlnumbercritical=crlnumbercritical;}
  
  public boolean getUseAuthorityKeyIdentifier(){ return useauthoritykeyidentifier;}
  public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier)
                {this.useauthoritykeyidentifier=useauthoritykeyidentifier;}
  
  public boolean getAuthorityKeyIdentifierCritical(){ return authoritykeyidentifiercritical;}
  public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical)
                {this.authoritykeyidentifiercritical=authoritykeyidentifiercritical;}
  
  public String getDefaultCRLDistPoint(){ return defaultcrldistpoint; }

  public void setDefaultCRLDistPoint(String defaultCRLDistPoint) {
      this.defaultcrldistpoint = defaultCRLDistPoint;
  }
  
  public String getDefaultCRLIssuer(){ return defaultcrlissuer; }
  public void setDefaultCRLIssuer(String defaultcrlissuer) {
      this.defaultcrlissuer = defaultcrlissuer;
  }
  
  public String getDefaultOCSPServiceLocator(){ return defaultocsplocator; }
  public void setDefaultOCSPServiceLocator(String defaultocsplocator) {
      this.defaultocsplocator = defaultocsplocator;
  }
  
  public String getCADefinedFreshestCRL(){ return this.cadefinedfreshestcrl; }

  public void setCADefinedFreshestCRL(String cADefinedFreshestCRL) {
      this.cadefinedfreshestcrl = cADefinedFreshestCRL;
  }

  public String getSubjectAltName(){ return subjectaltname; }
  public void setSubjectAltName(final String subjectaltname) {
      this.subjectaltname = subjectaltname;
  }
  public boolean getUseUTF8PolicyText() { return useUTF8PolicyText; } 
  public void setUseUTF8PolicyText(final boolean useUTF8PolicyText) { 
      this.useUTF8PolicyText = useUTF8PolicyText; 
  } 
  
  public boolean getUsePrintableStringSubjectDN() { return usePrintableStringSubjectDN; }
  public void setUsePrintableStringSubjectDN(final boolean usePrintableStringSubjectDN) { 
      this.usePrintableStringSubjectDN = usePrintableStringSubjectDN; 
  } 
  
  public boolean getUseLdapDnOrder() { return useLdapDNOrder; }
  public void setUseLdapDnOrder(final boolean useLdapDNOrder) { 
      this.useLdapDNOrder = useLdapDNOrder; 
  } 

  public boolean getUseCrlDistributionPointOnCrl() {
      return this.useCrlDistributionPointOnCrl;
  }

  public void setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl) {
      this.useCrlDistributionPointOnCrl = useCrlDistributionPointOnCrl;
  }

  public boolean getCrlDistributionPointOnCrlCritical() {
      return this.crlDistributionPointOnCrlCritical;
  }
  public void setCrlDistributionPointOnCrlCritical(boolean crlDistributionPointOnCrlCritical) {
      this.crlDistributionPointOnCrlCritical = crlDistributionPointOnCrlCritical;
  }
  
  public String getCmpRaAuthSecret() { return cmpRaAuthSecret; }
  public void setCmpRaAuthSecret(String cmpRaAuthSecret) { this.cmpRaAuthSecret = cmpRaAuthSecret; }

    public List<String> getAuthorityInformationAccess() {
        return authorityInformationAccess;
    }

    public void setAuthorityInformationAccess(List<String> authorityInformationAccess) {
        this.authorityInformationAccess = authorityInformationAccess;
    }
  
}