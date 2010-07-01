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
 
package org.ejbca.core.model.ca.caadmin;

import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;


/**
 * Holds non-sensitive information about a X509CA.
 *
 * @version $Id$
 */
public class X509CAInfo extends CAInfo{
   
  private List policies;
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

    
    /**
     * Constructor that should be used when creating CA and retrieving CA info.
     */
    public X509CAInfo(String subjectdn, String name, int status, Date updateTime, String subjectaltname, int certificateprofileid, 
                    long validity, Date expiretime, int catype, int signedby, Collection certificatechain, 
                    CATokenInfo catokeninfo, String description, int revokationreason, Date revokationdate, List policies,
                    long crlperiod, long crlIssueInterval, long crlOverlapTime, long deltacrlperiod, Collection crlpublishers,
                    boolean useauthoritykeyidentifier, boolean authoritykeyidentifiercritical,
                    boolean usecrlnumber, boolean crlnumbercritical, String defaultcrldistpoint, String defaultcrlissuer, String defaultocspservicelocator, String cadefinedfreshestcrl, boolean finishuser,
                    Collection extendedcaserviceinfos, boolean useUTF8PolicyText, Collection approvalSettings, int numOfReqApprovals, boolean usePrintableStringSubjectDN, boolean useLdapDnOrder,
                    boolean useCrlDistributionPointOnCrl, boolean crlDistributionPointOnCrlCritical, boolean includeInHealthCheck,
                    boolean _doEnforceUniquePublicKeys, boolean _doEnforceUniqueDistinguishedName, boolean _doEnforceUniqueSubjectDNSerialnumber,
                    boolean _useCertReqHistory) {
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
		        X509Certificate[] certs = (X509Certificate[])certificatechain.toArray(new X509Certificate[0]);
		        ArrayList list = CertTools.getCertCollectionFromArray(certs, null);
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
        this.revokationreason = revokationreason;
        this.revokationdate = revokationdate;
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
    }

    /**
     * Constructor that should be used when updating CA data.
     * Used by the web. Jsp and stuff like that.
     */
    public X509CAInfo(int caid, long validity, CATokenInfo catokeninfo, String description,
                      long crlperiod, long crlIssueInterval, long crlOverlapTime, long deltacrlperiod, 
                      Collection crlpublishers,
                      boolean useauthoritykeyidentifier, boolean authoritykeyidentifiercritical,
                      boolean usecrlnumber, boolean crlnumbercritical, String defaultcrldistpoint, String defaultcrlissuer, String defaultocspservicelocator, String cadefinedfreshestcrl,
                      boolean finishuser, Collection extendedcaserviceinfos, 
                      boolean useUTF8PolicyText, Collection approvalSettings, int numOfReqApprovals, boolean usePrintableStringSubjectDN, boolean useLdapDnOrder,
                      boolean useCrlDistributionPointOnCrl, boolean crlDistributionPointOnCrlCritical, boolean includeInHealthCheck,
                      boolean _doEnforceUniquePublicKeys, boolean _doEnforceUniqueDistinguishedName, boolean _doEnforceUniqueSubjectDNSerialnumber,
                      boolean _useCertReqHistory) {        
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
    }  
  
  
  public X509CAInfo(){}
    
  public List getPolicies() {
	  return this.policies;
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
  
  public String getDefaultOCSPServiceLocator(){ return defaultocsplocator; }
  
  public String getCADefinedFreshestCRL(){ return this.cadefinedfreshestcrl; }

  public void setCADefinedFreshestCRL(String cADefinedFreshestCRL) {
      this.cadefinedfreshestcrl = cADefinedFreshestCRL;
  }

  public String getSubjectAltName(){ return subjectaltname; }
  
  public boolean getUseUTF8PolicyText() { return useUTF8PolicyText; } 
  
  public boolean getUsePrintableStringSubjectDN() { return usePrintableStringSubjectDN; }
  
  public boolean getUseLdapDnOrder() { return useLdapDNOrder; }

  public boolean getUseCrlDistributionPointOnCrl() {
      return this.useCrlDistributionPointOnCrl;
  }

  public void setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl) {
      this.useCrlDistributionPointOnCrl = useCrlDistributionPointOnCrl;
  }

  public boolean getCrlDistributionPointOnCrlCritical() {
      return this.crlDistributionPointOnCrlCritical;
  }
}