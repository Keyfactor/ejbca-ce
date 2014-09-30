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

package org.ejbca.core.protocol.xkms.generators;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.crl.CrlStoreSession;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.config.GlobalConfigurationSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.w3._2002._03.xkms_.KeyBindingAbstractType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3c.dom.Document;

/**
 * Class generating a response for a register call
 * 
 *
 * @version $Id$
 */

public class RegisterResponseGenerator extends KRSSResponseGenerator {
	private static final Logger log = Logger.getLogger(RegisterResponseGenerator.class);

	public RegisterResponseGenerator(String remoteIP, RegisterRequestType req, Document requestDoc,
    		CaSession casession, EndEntityAuthenticationSession authenticationSession, CertificateStoreSession certificateStoreSession, EndEntityAccessSession endEntityAccessSession,
    		EndEntityProfileSession endEntityProfileSession, KeyRecoverySession keyRecoverySession, GlobalConfigurationSession globalConfigurationSession,
    		SignSession signSession, EndEntityManagementSession endEntityManagementSession, CrlStoreSession crlSession) {
		super(remoteIP, req,requestDoc, casession, authenticationSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, endEntityManagementSession, crlSession);
	}
	
	/**
	 * Returns a register response
	 */
	public RegisterResultType getResponse(boolean requestVerifies){
		RegisterResultType result = xkmsFactory.createRegisterResultType();		
		super.populateResponse(result, requestVerifies);		
		RegisterRequestType req = (RegisterRequestType) this.req;

		if(resultMajor == null){ 		
			if(!checkValidRespondWithRequest(req.getRespondWith(),false)){
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
			}
			if(resultMajor == null){ 
                PublicKey publicKey = getPublicKey(req);
                if (confirmPOP(publicKey)) {
                    String subjectDN = getSubjectDN(req);
                    List<EndEntityInformation> userDataList = findUserData(subjectDN);
                    EndEntityInformation userData = (userDataList.size() > 0 ? userDataList.get(0) : null);
                    if(userDataList.size() > 1) {
                        log.warn("Multiple end entities with subject DN " + subjectDN + " were found. This may lead to unexpected behavior.");
                    }
                    if (userData != null) {
                        String password = "";
                        boolean encryptedPassword = isPasswordEncrypted(req);
                        if (encryptedPassword) {
                            password = getEncryptedPassword(requestDoc, userData.getPassword());
                        } else {
                            password = getClearPassword(req, userData.getPassword());
                        }
                        String revocationCode = getRevocationCode(req);
                        if (password != null) {
                            X509Certificate cert = registerReissueOrRecover(false, false, result, userData, password, publicKey, revocationCode);
                            if (cert != null) {
                                KeyBindingAbstractType keyBinding = getResponseValues(req.getPrototypeKeyBinding(), cert, false, true);
                                result.getKeyBinding().add((KeyBindingType) keyBinding);
                            }
                        }
                    }
                }
			}
		}
		if(resultMajor == null){ 
			resultMajor = XKMSConstants.RESULTMAJOR_SUCCESS;
		}
		setResult(result);		
		return result;
	}

	/**
	 * Method extracting the public key from the message.
	 * @param req the request
	 * @return the public key or null if no public key could be found.
	 */
	protected PublicKey getPublicKey(RegisterRequestType req){
		Object retval = getPublicKeyInfo(req, true);
		if(retval instanceof X509Certificate){
			retval = ((X509Certificate) retval).getPublicKey();
		}
		return (PublicKey) retval;
	}
}
