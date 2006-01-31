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

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.IHardCAToken;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.RevokedInfoView;


/**
 * A class representing a view of a CA Information view..
 *
 * @version $Id: CAInfoView.java,v 1.2 2006-01-31 14:34:51 herrvendil Exp $
 */
public class CAInfoView implements java.io.Serializable, Cloneable {
    // Public constants.

   public static int NAME                    = 0;  
   public static int SUBJECTDN               = 1;   
   public static int SUBJECTALTNAME          = 2;
   public static int CATYPE                  = 3;
   
   public static int EXPIRETIME              = 5;
   public static int STATUS                  = 6;
   public static int CATOKEN_STATUS          = 7;
   public static int DESCRIPTION             = 8;
   
   public static int CRLPERIOD               = 10;
   public static int CRLPUBLISHERS           = 11;
   
   public static int OCSP                    = 13;
  
    
   public static String[] X509CA_CAINFODATATEXTS = {"NAME","SUBJECTDN","SUBJECTALTNAME","CATYPE","",
                                                    "EXPIRES","STATUS","CATOKENSTATUS","DESCRIPTION","", "CRLPERIOD", 
                                                    "CRLPUBLISHERS", "", "OCSPSERVICE"};
   
   private String[] cainfodata = null;
   private String[] cainfodatatexts = null;
   
   private CAInfo          cainfo   = null;
   private X509Certificate ocspcert = null; 
   
    public CAInfoView(CAInfo cainfo, EjbcaWebBean ejbcawebbean, HashMap publishersidtonamemap){
      this.cainfo = cainfo;  
        
      if(cainfo instanceof X509CAInfo){
        cainfodatatexts = new String[X509CA_CAINFODATATEXTS.length];
        cainfodata = new String[X509CA_CAINFODATATEXTS.length];  
        
        for(int i=0; i < X509CA_CAINFODATATEXTS.length; i++){
          if(X509CA_CAINFODATATEXTS[i].equals(""))
              cainfodatatexts[i]="&nbsp;";
          else
              cainfodatatexts[i] = ejbcawebbean.getText(X509CA_CAINFODATATEXTS[i]);
        }
        
        cainfodata[SUBJECTDN]  = cainfo.getSubjectDN();
        cainfodata[SUBJECTALTNAME] = ((X509CAInfo) cainfo).getSubjectAltName();
        cainfodata[NAME]       = cainfo.getName();
        cainfodata[CATYPE]     = ejbcawebbean.getText("X509");
        cainfodata[4]          = "&nbsp;"; // blank line
        if(cainfo.getExpireTime() == null)
		  cainfodata[EXPIRETIME] = "";
		else
          cainfodata[EXPIRETIME] = ejbcawebbean.printDateTime(cainfo.getExpireTime());
        
        switch(cainfo.getStatus()){
            case SecConst.CA_ACTIVE :
              cainfodata[STATUS]     = ejbcawebbean.getText("ACTIVE");     
              break;
            case SecConst.CA_EXPIRED :
              cainfodata[STATUS]     = ejbcawebbean.getText("EXPIRED");
              break;
            case SecConst.CA_OFFLINE :
              cainfodata[STATUS]     = ejbcawebbean.getText("OFFLINE");
              break;
            case SecConst.CA_REVOKED :
              cainfodata[STATUS]     = ejbcawebbean.getText("CAREVOKED") + "<br>&nbsp;&nbsp;" + 
                                                    ejbcawebbean.getText("REASON") + " : <br>&nbsp;&nbsp;&nbsp;&nbsp;" + 
                                                    ejbcawebbean.getText(RevokedInfoView.reasontexts[cainfo.getRevokationReason()]) + "<br>&nbsp;&nbsp;" +
			                                        ejbcawebbean.getText("REVOKATIONDATE") + "<br>&nbsp;&nbsp;&nbsp;&nbsp;" + 
			                                        ejbcawebbean.printDateTime(cainfo.getRevokationDate());
              break;
            case SecConst.CA_WAITING_CERTIFICATE_RESPONSE :
              cainfodata[STATUS]     = ejbcawebbean.getText("WAITINGFORCERTRESPONSE");
              break;              
        } 
        
        if(cainfo.getCATokenInfo() instanceof HardCATokenInfo){
        	switch(((HardCATokenInfo) cainfo.getCATokenInfo()).getCATokenStatus()){
              case IHardCAToken.STATUS_ACTIVE :
            	cainfodata[CATOKEN_STATUS]     = ejbcawebbean.getText("HARDTOKEN") + ", " + ejbcawebbean.getText("ACTIVE");     
            	break;
              case IHardCAToken.STATUS_OFFLINE :
            	cainfodata[CATOKEN_STATUS]     = ejbcawebbean.getText("HARDTOKEN") +", " + ejbcawebbean.getText("OFFLINE");
            	break;
        	}
        }else{
        	cainfodata[CATOKEN_STATUS]     = ejbcawebbean.getText("SOFT") + ", " + ejbcawebbean.getText("ACTIVE");
        }

        
        cainfodata[DESCRIPTION] = cainfo.getDescription();
        
		cainfodata[9]          = "&nbsp;"; // blank line

        cainfodata[CRLPERIOD] = Integer.toString(((X509CAInfo) cainfo).getCRLPeriod());
        
		cainfodata[CRLPUBLISHERS] = "";
        Iterator iter = ((X509CAInfo) cainfo).getCRLPublishers().iterator();
        if(iter.hasNext())
		  cainfodata[CRLPUBLISHERS] = (String) publishersidtonamemap.get(iter.next()); 
        else
		cainfodata[CRLPUBLISHERS] = ejbcawebbean.getText("NONE");
        
        while(iter.hasNext())
			cainfodata[CRLPUBLISHERS] = cainfodata[CRLPUBLISHERS] + ", " +
			                                               (String) publishersidtonamemap.get(iter.next());
        
		cainfodata[12]          = "&nbsp;"; // blank line
		
		boolean active = false;		
		iter = ((X509CAInfo) cainfo).getExtendedCAServiceInfos().iterator();
		while(iter.hasNext()){
	      ExtendedCAServiceInfo next = (ExtendedCAServiceInfo) iter.next();
	      if(next instanceof OCSPCAServiceInfo){
	      	active = next.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE;
	      	if(((OCSPCAServiceInfo) next).getOCSPSignerCertificatePath() != null)
	      	  ocspcert = (X509Certificate) ((OCSPCAServiceInfo) next).getOCSPSignerCertificatePath().get(0);		  
	      }
		}
		
		if(active){
	      cainfodata[OCSP] = ejbcawebbean.getText("ACTIVE") + 
                             "<br>" + "&nbsp;<a style='cursor:hand;' onClick='viewocspcert()'><u>" +
			                 ejbcawebbean.getText("VIEWOCSPCERTIFICATE") + 
			                 "</u></a>";	
		}else{
		  cainfodata[OCSP] = ejbcawebbean.getText("INACTIVE");	
		}
       
        
      }
   }

   public String[] getCAInfoData(){ return cainfodata;}
   public String[] getCAInfoDataText(){ return cainfodatatexts;} 

   public CAInfo getCAInfo() { return cainfo;}
   public Collection getCertificateChain() { return cainfo.getCertificateChain(); }
   
   public X509Certificate getOCSPSignerCertificate() { return ocspcert;}
   
   
}
