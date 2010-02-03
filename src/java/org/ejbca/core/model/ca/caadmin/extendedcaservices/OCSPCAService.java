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
 
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.util.CryptoProviderTools;

/** Handles and maintains the CA-part of the OCSP functionality
 * 
 * @version $Id$
 */
public class OCSPCAService extends ExtendedCAService implements java.io.Serializable {

    private static Logger log = Logger.getLogger(OCSPCAService.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    public static final float LATEST_VERSION = 3; 
    
    public static final String SERVICENAME = "OCSPCASERVICE";

    private OCSPCAServiceInfo info = null;  
    
    /** kept for upgrade purposes 3.9 -> 3.10 */
    private static final String OCSPKEYSTORE   = "ocspkeystore"; 
    private static final String KEYSPEC        = "keyspec";
	private static final String KEYALGORITHM   = "keyalgorithm";
	private static final String SUBJECTDN      = "subjectdn";
	private static final String SUBJECTALTNAME = "subjectaltname";

	/** kept for upgrade purposes 3.3 -> 3.4 */
    private static final String KEYSIZE        = "keysize";
            
    public OCSPCAService(ExtendedCAServiceInfo serviceinfo)  {
      log.debug("OCSPCAService : constructor " + serviceinfo.getStatus()); 
      CryptoProviderTools.installBCProvider();
      data = new HashMap();   
      data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE));
	  setStatus(serviceinfo.getStatus());
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public OCSPCAService(HashMap data) {
    	loadData(data);
    }

   /* 
	* @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void init(CA ca) throws Exception {
	   log.debug("OCSPCAService : init ");
	   OCSPCAServiceInfo info = (OCSPCAServiceInfo) getExtendedCAServiceInfo();       
	   setStatus(info.getStatus());
   }   

   /* 
	* @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void update(ExtendedCAServiceInfo serviceinfo, CA ca) throws Exception {		   
	   log.debug("OCSPCAService : update " + serviceinfo.getStatus());
	   setStatus(serviceinfo.getStatus());
	   // Only status is updated
	   this.info = new OCSPCAServiceInfo(serviceinfo.getStatus());
   }

	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
        log.trace(">extendedService");
        if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			String msg = intres.getLocalizedMessage("caservice.notactive");
			log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
        }
        if (!(request instanceof OCSPCAServiceRequest)) {
            throw new IllegalExtendedCAServiceRequestException();            
        }
        OCSPCAServiceRequest ocspServiceReq = (OCSPCAServiceRequest)request;
    	PrivateKey privKey = ocspServiceReq.getPrivKey();
    	String providerName = ocspServiceReq.getPrivKeyProvider();
        ExtendedCAServiceResponse returnval = OCSPUtil.createOCSPCAServiceResponse(ocspServiceReq, privKey, providerName, (X509Certificate[])ocspServiceReq.getCertificateChain().toArray(new X509Certificate[0]));
        log.trace("<extendedService");		  		
		return returnval;
	}

	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	public void upgrade() {
		if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
			String msg = intres.getLocalizedMessage("ocspcaservice.upgrade", new Float(getVersion()));
			log.info(msg);
			data.remove(KEYALGORITHM);
			data.remove(KEYSIZE);
			data.remove(KEYSPEC);
			data.remove(OCSPKEYSTORE);
			data.remove(SUBJECTALTNAME);
			data.remove(SUBJECTDN);
			data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}

	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#getExtendedCAServiceInfo()
	 */
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {		
		if(info == null) {
		  info = new OCSPCAServiceInfo(getStatus());
		}
		return this.info;
	}
}

