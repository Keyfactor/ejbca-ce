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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.util.HTMLTools;

/**
 * A class representing a view of a CA Information view..
 *
 * @version $Id$
 */
public class CAInfoView implements Serializable, Cloneable {

	private static final long serialVersionUID = -5154282635821412670L;
    // Public constants.

   public static final int NAME                    = 0;  
   public static final int SUBJECTDN               = 1;   
   public static final int SUBJECTALTNAME          = 2;
   public static final int CATYPE                  = 3;
   
   private static final int CASPACER               = 4;
   
   public static final int EXPIRETIME              = 5;
   public static final int STATUS                  = 6;
   public static final int CATOKEN_STATUS          = 7;
   public static final int DESCRIPTION             = 8;
   
   private static final int CRLSPACER              = 9;
   
   public static final int CRLPERIOD               = 10;
   public static final int CRLISSUEINTERVAL        = 11;
   public static final int CRLOVERLAPTIME          = 12;
   public static final int DELTACRLPERIOD          = 13;
   public static final int CRLPUBLISHERS           = 14;
   
   private static final int OCSPSPACER             = 15;
   
   public static final int OCSP                    = 16;
  
    
   /** A info text strings must contain:
    * CANAME, CERT_SUBJECTDN, EXT_PKIX_SUBJECTALTNAME, CATYPE, EXPIRES, STATUS, CATOKENSTATUS, DESCRIPTION, CRL_CA_CRLPERIOD, CRL_CA_ISSUEINTERVAL, CRL_CA_OVERLAPTIME, CRL_CA_DELTACRLPERIOD
    * It must also have "" in pos nr 4 (CASPACER) 
    * It must also have "" in pos nr 9 (CRLSPACER) 
    */
   public static String[] X509CA_CAINFODATATEXTS = {"CANAME","CERT_SUBJECTDN","EXT_PKIX_SUBJECTALTNAME","CATYPE","",
                                                    "EXPIRES","STATUS","CATOKENSTATUS","DESCRIPTION","", "CRL_CA_CRLPERIOD", 
                                                    "CRL_CA_ISSUEINTERVAL", "CRL_CA_OVERLAPTIME", "CRL_CA_DELTACRLPERIOD", "PUBLISHERS", "", "OCSPSERVICE"};

   public static String[] CVCCA_CAINFODATATEXTS = {"NAME","CERT_SUBJECTDN","","CATYPE","",
       "EXPIRES","STATUS","CATOKENSTATUS","DESCRIPTION","", "CRL_CA_CRLPERIOD", 
       "CRL_CA_ISSUEINTERVAL", "CRL_CA_OVERLAPTIME", "CRL_CA_DELTACRLPERIOD"};

   private String[] cainfodata = null;
   private String[] cainfodatatexts = null;
   
   private CAInfo          cainfo   = null;
   
    public CAInfoView(CAInfo cainfo, EjbcaWebBean ejbcawebbean, Map<Integer, String> publishersidtonamemap){
      this.cainfo = cainfo;  
        
      if (cainfo instanceof X509CAInfo) {
        setupGeneralInfo(X509CA_CAINFODATATEXTS, cainfo, ejbcawebbean);

        cainfodata[SUBJECTALTNAME] = HTMLTools.htmlescape(((X509CAInfo) cainfo).getSubjectAltName());

		cainfodata[CRLPUBLISHERS] = "";
        Iterator<Integer> publisherIds = ((X509CAInfo) cainfo).getCRLPublishers().iterator();
        if(publisherIds.hasNext()) {
        	cainfodata[CRLPUBLISHERS] = publishersidtonamemap.get(publisherIds.next()); 
        } else {
        	cainfodata[CRLPUBLISHERS] = ejbcawebbean.getText("NONE");
        }
        
        while(publisherIds.hasNext()) {
			cainfodata[CRLPUBLISHERS] = cainfodata[CRLPUBLISHERS] + ", " + (String) publishersidtonamemap.get(publisherIds.next());
        }
        
		cainfodata[OCSPSPACER]          = "&nbsp;"; // blank line
		
		boolean active = false;		
		Iterator<ExtendedCAServiceInfo> extendedServiceInfoIterator = ((X509CAInfo) cainfo).getExtendedCAServiceInfos().iterator();
		while(publisherIds.hasNext()){
	      ExtendedCAServiceInfo next = extendedServiceInfoIterator.next();
	      if(next instanceof OCSPCAServiceInfo){
	      	active = next.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE;
	      }
		}
		
		if(active){
	      cainfodata[OCSP] = ejbcawebbean.getText("ACTIVE");	
		}else{
		  cainfodata[OCSP] = ejbcawebbean.getText("INACTIVE");	
		}
       
        
      } else if (cainfo instanceof CVCCAInfo) {
          setupGeneralInfo(CVCCA_CAINFODATATEXTS, cainfo, ejbcawebbean);          
      }
   }

	private void setupGeneralInfo(String[] strings, CAInfo cainfo, EjbcaWebBean ejbcawebbean) {
		cainfodatatexts = new String[strings.length];
        cainfodata = new String[strings.length];  
        
        for(int i=0; i < strings.length; i++){
          if(strings[i].equals("")) {
              cainfodatatexts[i]="&nbsp;";
          } else {
              cainfodatatexts[i] = ejbcawebbean.getText(strings[i]);
          }
        }
        
        cainfodata[SUBJECTDN]  = HTMLTools.htmlescape(cainfo.getSubjectDN());
        cainfodata[NAME]       = HTMLTools.htmlescape(cainfo.getName());
        int catype = cainfo.getCAType();
        if (catype == CAInfo.CATYPE_CVC) {
            cainfodata[CATYPE]     = ejbcawebbean.getText("CVCCA");        	
        } else {
            cainfodata[CATYPE]     = ejbcawebbean.getText("X509");        	
        }
        cainfodata[CASPACER]          = "&nbsp;"; // blank line
        if(cainfo.getExpireTime() == null) {
		  cainfodata[EXPIRETIME] = "";
        } else {
          cainfodata[EXPIRETIME] = ejbcawebbean.formatAsISO8601(cainfo.getExpireTime());
        }
        
        switch(cainfo.getStatus()){
            case CAConstants.CA_ACTIVE :
              cainfodata[STATUS]     = ejbcawebbean.getText("ACTIVE");     
              break;
            case CAConstants.CA_EXPIRED :
              cainfodata[STATUS]     = ejbcawebbean.getText("EXPIRED");
              break;
            case CAConstants.CA_OFFLINE :
              cainfodata[STATUS]     = ejbcawebbean.getText("OFFLINE");
              break;
            case CAConstants.CA_REVOKED :
              cainfodata[STATUS]     = ejbcawebbean.getText("CAREVOKED") + "<br>&nbsp;&nbsp;" + 
                                                    ejbcawebbean.getText("REASON") + " : <br>&nbsp;&nbsp;&nbsp;&nbsp;" + 
                                                    ejbcawebbean.getText(SecConst.reasontexts[cainfo.getRevocationReason()]) + "<br>&nbsp;&nbsp;" +
			                                        ejbcawebbean.getText("CRL_ENTRY_REVOCATIONDATE") + "<br>&nbsp;&nbsp;&nbsp;&nbsp;" + 
			                                        ejbcawebbean.formatAsISO8601(cainfo.getRevocationDate());
              break;
            case CAConstants.CA_WAITING_CERTIFICATE_RESPONSE :
              cainfodata[STATUS]     = ejbcawebbean.getText("WAITINGFORCERTRESPONSE");
              break;              
            case CAConstants.CA_EXTERNAL :
                cainfodata[STATUS]     = ejbcawebbean.getText("EXTERNALCA");
                break;              
        } 

        String tokentext = ejbcawebbean.getText("SOFT");
        if(cainfo.getCATokenInfo().getClassPath().equals(PKCS11CryptoToken.class.getName())) {
        	tokentext = ejbcawebbean.getText("HARDTOKEN");
        }
        if(cainfo.getCATokenInfo().getClassPath().equals(NullCryptoToken.class.getName())) {
        	tokentext = ejbcawebbean.getText("EXTERNALCA");
        }
        switch(cainfo.getCATokenInfo().getTokenStatus()) {
        case CryptoToken.STATUS_ACTIVE :
        	cainfodata[CATOKEN_STATUS]     =  tokentext + ", " + ejbcawebbean.getText("ACTIVE");     
        	break;
        case CryptoToken.STATUS_OFFLINE :
        	cainfodata[CATOKEN_STATUS]     = tokentext +", " + ejbcawebbean.getText("OFFLINE");
        	break;
        }
        
        cainfodata[DESCRIPTION] = HTMLTools.htmlescape(cainfo.getDescription());
        
		cainfodata[CRLSPACER]          = "&nbsp;"; // blank line

        cainfodata[CRLPERIOD] = SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
        cainfodata[CRLISSUEINTERVAL] = SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES);
        cainfodata[CRLOVERLAPTIME] = SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES);
        cainfodata[DELTACRLPERIOD] = SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES);
	}

   public String[] getCAInfoData(){ return cainfodata;}
   public String[] getCAInfoDataText(){ return cainfodatatexts;} 

   public CAInfo getCAInfo() { return cainfo;}
   public CATokenInfo getCATokenInfo() { return cainfo.getCATokenInfo(); }
   public Collection<Certificate> getCertificateChain() { return cainfo.getCertificateChain(); }
}
