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

import java.security.cert.X509Certificate;

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
import org.w3._2002._03.xkms_.RecoverRequestType;
import org.w3._2002._03.xkms_.RecoverResultType;
import org.w3c.dom.Document;

/**
 * Class generating a response for a recover call
 *
 * @version $Id$
 */

public class RecoverResponseGenerator extends KRSSResponseGenerator {
	//private static Logger log = Logger.getLogger(RecoverResponseGenerator.class);

	public RecoverResponseGenerator(String remoteIP, RecoverRequestType req, Document requestDoc,
    		CaSession caadminsession, EndEntityAuthenticationSession authenticationSession, CertificateStoreSession certificateStoreSession, EndEntityAccessSession endEntityAccessSession,
    		EndEntityProfileSession endEntityProfileSession, KeyRecoverySession keyRecoverySession, GlobalConfigurationSession globalConfigurationSession,
    		SignSession signSession, EndEntityManagementSession endEntityManagementSession, CrlStoreSession crlSession) {
		super(remoteIP, req,requestDoc, caadminsession, authenticationSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, endEntityManagementSession, crlSession);
	}
	
	/**
	 * Returns a register response
	 */
	public RecoverResultType getResponse(boolean requestVerifies){
		RecoverResultType result = xkmsFactory.createRecoverResultType();		
		super.populateResponse(result, requestVerifies);		
		RecoverRequestType req = (RecoverRequestType) this.req;
		

		if(resultMajor == null){ 		
			if(!checkValidRespondWithRequest(req.getRespondWith(),false)){
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
			}

			if(resultMajor == null){ 				
				if(resultMajor == null){ 
					X509Certificate cert = (X509Certificate) getPublicKeyInfo(req, false);					
					
					EndEntityInformation userData = findUserData(cert);
					if(userData != null){
						String password = "";	
						boolean encryptedPassword = isPasswordEncrypted(req);
						if(encryptedPassword){
							password = getEncryptedPassword(requestDoc, userData.getPassword());
						}else{
							password = getClearPassword(req, userData.getPassword());
						}

						if(password != null ){
							X509Certificate newCert = registerReissueOrRecover(true,false, result, userData,password,  cert.getPublicKey(), null);
							if(newCert != null){
								KeyBindingAbstractType keyBinding = getResponseValues(req.getRecoverKeyBinding(), newCert, false, true);
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


	



	
}
