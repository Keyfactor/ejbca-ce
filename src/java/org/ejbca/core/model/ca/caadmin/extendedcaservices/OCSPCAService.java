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

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.protocol.ocsp.OCSPUtil;

/** Handles and maintains the CA-part of the OCSP functionality
 * 
 * @version $Id$
 */
public class OCSPCAService extends ExtendedCAService implements Serializable {

    private static Logger log = Logger.getLogger(OCSPCAService.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    public static final float LATEST_VERSION = 4; 
    
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
            
    public OCSPCAService(final ExtendedCAServiceInfo serviceinfo)  {
    	super(serviceinfo);
    	log.debug("OCSPCAService : constructor " + serviceinfo.getStatus());
    	CryptoProviderTools.installBCProviderIfNotAvailable();
    	data = new LinkedHashMap<Object, Object>();
		data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());	// For integration with CESeCore
		data.put(EXTENDEDCASERVICETYPE, Integer.valueOf(ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE));	// For current version of EJBCA
    	setStatus(serviceinfo.getStatus());
    	data.put(VERSION, new Float(LATEST_VERSION));
    }

    public OCSPCAService(final HashMap data) {
    	super(data);
    	loadData(data);
    }

    @Override
    public void init(final CA ca) throws Exception {
    	log.debug("OCSPCAService : init ");
    	setCA(ca);
    	final OCSPCAServiceInfo info = (OCSPCAServiceInfo) getExtendedCAServiceInfo();       
    	setStatus(info.getStatus());
    }   

    @Override
    public void update(final ExtendedCAServiceInfo serviceinfo, final CA ca) {		   
    	log.debug("OCSPCAService : update " + serviceinfo.getStatus());
    	setStatus(serviceinfo.getStatus());
    	// Only status is updated
    	this.info = new OCSPCAServiceInfo(serviceinfo.getStatus());
    	setCA(ca);
    }

    @Override
	public ExtendedCAServiceResponse extendedService(final ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
        log.trace(">extendedService");
        if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			String msg = intres.getLocalizedMessage("caservice.notactive");
			log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
        }
        if (!(request instanceof OCSPCAServiceRequest)) {
            throw new IllegalExtendedCAServiceRequestException();            
        }

        final OCSPCAServiceRequest ocspServiceReq = (OCSPCAServiceRequest)request;
        try {
        	final PrivateKey privKey = getCa().getCAToken().getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        	final String providerName = getCa().getCAToken().getCryptoToken().getSignProviderName();
        	final X509Certificate[] signerChain = (X509Certificate[])getCa().getCertificateChain().toArray(new X509Certificate[0]);
        	final ExtendedCAServiceResponse returnval = OCSPUtil.createOCSPCAServiceResponse(
        			ocspServiceReq, privKey, providerName, signerChain);
            log.trace("<extendedService");		  		
        	return returnval;
        } catch (CryptoTokenOfflineException e) {
			throw new ExtendedCAServiceNotActiveException(e);
		} catch (IllegalCryptoTokenException e) {
			throw new ExtendedCAServiceNotActiveException(e);
		}
	}

    @Override
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

    @Override
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
	    	data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());	// For integration with CESeCore
			data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}

    @Override
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {		
		if(info == null) {
		  info = new OCSPCAServiceInfo(getStatus());
		}
		return this.info;
	}
}

