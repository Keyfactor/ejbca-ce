/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.InternalEjbcaResources;

/** Handles and maintains the CA-part of the Hard token encrypt functionality
 * 
 * @version $Id$
 */
public class HardTokenEncryptCAService extends ExtendedCAService implements Serializable {

    private static final long serialVersionUID = 2126714932597569623L;
    private static Logger log = Logger.getLogger(HardTokenEncryptCAService.class);
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

	public static final float LATEST_VERSION = 1; 

	public static final String SERVICENAME = "HARDTOKENENCRYPTCASERVICE";

	public HardTokenEncryptCAService(final ExtendedCAServiceInfo serviceinfo)  {
		super(serviceinfo);
		log.debug("HardTokenEncryptCAService : constructor " + serviceinfo.getStatus());
		CryptoProviderTools.installBCProviderIfNotAvailable();
		data = new LinkedHashMap<Object, Object>();
		data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());
		data.put(EXTENDEDCASERVICETYPE, Integer.valueOf(ExtendedCAServiceTypes.TYPE_HARDTOKENENCEXTENDEDSERVICE));
		data.put(VERSION, new Float(LATEST_VERSION));
		setStatus(serviceinfo.getStatus());
	}

	public HardTokenEncryptCAService(final HashMap<?, ?> data) {
		super(data);
		CryptoProviderTools.installBCProviderIfNotAvailable();
		loadData(data);
	}

	@Override
	public void init(final CryptoToken cryptoToken, final CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception {
		log.debug("OCSPCAService : init ");
		setCA(ca);
		final ExtendedCAServiceInfo info = getExtendedCAServiceInfo();
		setStatus(info.getStatus());
	}   

	@Override
	public void update(final CryptoToken cryptoToken, final ExtendedCAServiceInfo serviceinfo, final CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) {		   
		log.debug("OCSPCAService : update " + serviceinfo.getStatus());
		setStatus(serviceinfo.getStatus());
		setCA(ca);
	}

	@Override
	public ExtendedCAServiceResponse extendedService(final CryptoToken cryptoToken, final ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
		log.trace(">extendedService");
		if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			String msg = intres.getLocalizedMessage("caservice.notactive", "HardTokenEncrypt");
			log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
		}
		if (!(request instanceof HardTokenEncryptCAServiceRequest)) {
			throw new IllegalExtendedCAServiceRequestException("Not a HardTokenEncryptCAServiceRequest: "+request.getClass().getName());            
		}

		final HardTokenEncryptCAServiceRequest serviceReq = (HardTokenEncryptCAServiceRequest)request;
		ExtendedCAServiceResponse returnval = null; 
    	if(serviceReq.getCommand() == HardTokenEncryptCAServiceRequest.COMMAND_ENCRYPTDATA){
    		try{	
    			returnval = new HardTokenEncryptCAServiceResponse(HardTokenEncryptCAServiceResponse.TYPE_ENCRYPTRESPONSE, 
    					getCa().encryptData(cryptoToken, serviceReq.getData(), CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT));	
    		}catch(CMSException e){
    			log.error("encrypt:", e.getUnderlyingException());
    			throw new IllegalExtendedCAServiceRequestException(e);
    		}catch(Exception e){
    			throw new IllegalExtendedCAServiceRequestException(e);
    		}
    	}else{
    		if(serviceReq.getCommand() == HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA){
            try{
            	returnval = new HardTokenEncryptCAServiceResponse(HardTokenEncryptCAServiceResponse.TYPE_DECRYPTRESPONSE, 
            			getCa().decryptData(cryptoToken, serviceReq.getData(), CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT));
    		  }catch(CMSException e){
    			 log.error("decrypt:", e.getUnderlyingException());
  		  	 throw new IllegalExtendedCAServiceRequestException(e);
   		  }catch(Exception e){
    		  	 throw new IllegalExtendedCAServiceRequestException(e);
    		  }
    		}else{
    		  throw new IllegalExtendedCAServiceRequestException("Illegal command: "+serviceReq.getCommand()); 
    		}
    	}          	
		return returnval;
	}

	@Override
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	@Override
	public void upgrade() {
		if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
			String msg = intres.getLocalizedMessage("caservice.upgrade", new Float(getVersion()));
			log.info(msg);
			data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}

	@Override
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {	
		return new HardTokenEncryptCAServiceInfo(getStatus());
	}
}

