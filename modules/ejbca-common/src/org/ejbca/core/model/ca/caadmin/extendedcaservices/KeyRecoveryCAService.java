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
import java.security.KeyPair;
import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
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
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.InternalEjbcaResources;

/** Handles and maintains the CA-part of the Key Recovery functionality
 * 
 * @version $Id$
 */
public class KeyRecoveryCAService extends ExtendedCAService implements Serializable {

	private static final long serialVersionUID = 2400252746958812175L;
    private static Logger log = Logger.getLogger(KeyRecoveryCAService.class);
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

	public static final float LATEST_VERSION = 1; 

	public static final String SERVICENAME = "KEYRECOVERYCASERVICE";

	public KeyRecoveryCAService(final ExtendedCAServiceInfo serviceinfo)  {
		super(serviceinfo);
		if (log.isDebugEnabled()) {
		    log.debug("KeyRecoveryCAService : constructor " + serviceinfo.getStatus());
		}
		CryptoProviderTools.installBCProviderIfNotAvailable();
		data = new LinkedHashMap<Object, Object>();
		data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());
		data.put(EXTENDEDCASERVICETYPE, Integer.valueOf(ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE));
		data.put(VERSION, new Float(LATEST_VERSION));
		setStatus(serviceinfo.getStatus());
	}

	public KeyRecoveryCAService(final HashMap<?, ?> data) {
		super(data);
		CryptoProviderTools.installBCProviderIfNotAvailable();
		loadData(data);
	}

	@Override
	public void init(CryptoToken cryptoToken, final CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("KeyRecoveryCAService : init ");
        }
		setCA(ca);
		final ExtendedCAServiceInfo info = getExtendedCAServiceInfo();
		setStatus(info.getStatus());
	}   

	@Override
	public void update(CryptoToken cryptoToken, final ExtendedCAServiceInfo serviceinfo, final CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) {		   
        if (log.isDebugEnabled()) {
            log.debug("KeyRecoveryCAService : update " + serviceinfo.getStatus());
        }
		setStatus(serviceinfo.getStatus());
		setCA(ca);
	}

	@Override
	public ExtendedCAServiceResponse extendedService(CryptoToken cryptoToken, final ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
		if (log.isTraceEnabled()) {
		    log.trace(">extendedService");
		}
		if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			String msg = intres.getLocalizedMessage("caservice.notactive", "KeyRecovery");
			log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
		}
		if (!(request instanceof KeyRecoveryCAServiceRequest)) {
			throw new IllegalExtendedCAServiceRequestException("Not a KeyRecoveryCAServiceRequest: "+request.getClass().getName());            
		}

		final KeyRecoveryCAServiceRequest serviceReq = (KeyRecoveryCAServiceRequest)request;
		ExtendedCAServiceResponse returnval = null; 
		if (serviceReq.getCommand() == KeyRecoveryCAServiceRequest.COMMAND_ENCRYPTKEYS) {
			try {
			    final String keyAlias = getCa().getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
                if (log.isDebugEnabled()) {
                    log.debug("Encrypting using alias '"+keyAlias+"' from crypto token "+cryptoToken.getId());
                }
	            // Creating the KeyId may just throw an exception, we will log this but store the cert and ignore the error
	            String keyId = null;
	            try {
	                keyId = new String(Base64.encode(KeyTools.createSubjectKeyId(cryptoToken.getPublicKey(keyAlias)).getKeyIdentifier(), false));
	            } catch (Exception e) { // NOPMD: we catch wide here because we do not want this to cause a transaction failure
	                log.warn("Error creating subjectKeyId for key recovery, cryptoToken: " + cryptoToken.getId() + ", keyAlias: " + keyAlias, e);
	            }
				returnval = new KeyRecoveryCAServiceResponse(KeyRecoveryCAServiceResponse.TYPE_ENCRYPTKEYSRESPONSE, 
						X509CA.encryptKeys(cryptoToken, keyAlias, serviceReq.getKeyPair()), cryptoToken.getId(), keyAlias, keyId);
			} catch(Exception e) {
				throw new IllegalExtendedCAServiceRequestException(e);
			}
		} else {
			if (serviceReq.getCommand() == KeyRecoveryCAServiceRequest.COMMAND_DECRYPTKEYS) {
				try {
				    String keyAlias = serviceReq.getKeyAlias();
				    final String defaultAlias = getCa().getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
				    if (StringUtils.isEmpty(keyAlias)) {
				        // If we haven't stored any key alias, in the entry, use the default one
                        keyAlias = defaultAlias;				        
				    }
				    KeyPair keys = null;
				    try {
				        if (log.isDebugEnabled()) {
				            log.debug("Trying to decrypt using alias '"+keyAlias+"' from crypto token "+cryptoToken.getId());
				        }
				        keys = X509CA.decryptKeys(cryptoToken, keyAlias, serviceReq.getKeyData());
				    } catch (Exception e) { // NOPMD: we have to catch wide here, using the wrong key to decrypt can result in several different errors
				        if (log.isDebugEnabled()) {
				            log.debug("Decryption with alias '"+keyAlias+"' failed, trying defaultAlias: ", e);
				        }
				        // Did we use the wrong key alias? Try with the default one, if we din't do that already
				        if (!StringUtils.equals(keyAlias, defaultAlias)) {
	                        if (log.isDebugEnabled()) {
	                            log.debug("Trying to decrypt using default alias '"+defaultAlias+"' from crypto token "+cryptoToken.getId());
	                        }
	                        keys = X509CA.decryptKeys(cryptoToken, defaultAlias, serviceReq.getKeyData());
				        } else {
				            // Just re-throw if we have nothing to test here
				            throw e;
				        }
				    }
	                // Creating the KeyId in String format may just throw an exception, we will log this but store the cert and ignore the error
	                String keyId = null;
	                try {
	                    keyId = new String(Base64.encode(KeyTools.createSubjectKeyId(cryptoToken.getPublicKey(keyAlias)).getKeyIdentifier(), false));
	                } catch (Exception e) {
	                    log.warn("Error creating subjectKeyId for key recovery, cryptoToken: " + cryptoToken.getId() + ", keyAlias: " + keyAlias, e);
	                }
					returnval = new KeyRecoveryCAServiceResponse(KeyRecoveryCAServiceResponse.TYPE_DECRYPTKEYSRESPONSE, 
							keys, cryptoToken.getId(), keyAlias, keyId);
                } catch(RuntimeException e) {
                    throw e; // Rethrow RuntimeExceptions, they always cause rollback
				} catch(Exception e) {
					throw new IllegalExtendedCAServiceRequestException(e);
				}
			} else {
				throw new IllegalExtendedCAServiceRequestException("Illegal command: "+serviceReq.getCommand()); 
			}
		}
        if (log.isTraceEnabled()) {
            log.trace("<extendedService");
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
		return new KeyRecoveryCAServiceInfo(getStatus());
	}
}

