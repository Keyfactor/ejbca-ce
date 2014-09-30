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

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.crl.CrlStoreSession;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.config.GlobalConfigurationSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.w3._2002._03.xkms_.KeyBindingAbstractType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.ReissueRequestType;
import org.w3._2002._03.xkms_.ReissueResultType;
import org.w3c.dom.Document;

/**
 * Class generating a response for a reissue call
 * 
 *
 * @version $Id$
 */

public class ReissueResponseGenerator extends KRSSResponseGenerator {
	private static Logger log = Logger.getLogger(ReissueResponseGenerator.class);

	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
	
	private EndEntityManagementSession endEntityManagementSession;
	
	public ReissueResponseGenerator(String remoteIP, ReissueRequestType req, Document requestDoc,
    		CaSession caadminsession, EndEntityAuthenticationSession authenticationSession, CertificateStoreSession certificateStoreSession, EndEntityAccessSession endEntityAccessSession,
    		EndEntityProfileSession endEntityProfileSession, KeyRecoverySession keyRecoverySession, GlobalConfigurationSession globalConfigurationSession,
    		SignSession signSession, EndEntityManagementSession endEntityManagementSession, CrlStoreSession crlSession) {
		super(remoteIP, req,requestDoc, caadminsession, authenticationSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, endEntityManagementSession, crlSession);
		this.endEntityManagementSession = endEntityManagementSession;
	}
	
	/**
	 * Returns a reissue response
	 */
	public ReissueResultType getResponse(boolean requestVerifies){
		ReissueResultType result = xkmsFactory.createReissueResultType();		
		super.populateResponse(result, requestVerifies);		
		ReissueRequestType req = (ReissueRequestType) this.req;
		// Variables defined here for debug reasons
		boolean isCertValid=false;
		EndEntityInformation userData = null;
		String password = "";
		X509Certificate newCert = null;
		if(resultMajor == null){ 		
			if(!checkValidRespondWithRequest(req.getRespondWith(),false)){
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
			}
			if(resultMajor == null){ 
			    X509Certificate cert = (X509Certificate) getPublicKeyInfo(req, false);
			    isCertValid = certIsValid(cert);
			    if(isCertValid && confirmPOP(cert.getPublicKey())){
			        userData = findUserData(cert);
			        if(userData != null){
			            boolean encryptedPassword = isPasswordEncrypted(req);
			            if(isCertValid && XKMSConfig.isAutomaticReissueAllowed()){
			                password = setUserStatusToNew(userData);
			            }else{							
			                if(encryptedPassword){
			                    password = getEncryptedPassword(requestDoc, userData.getPassword());
			                }else{
			                    password = getClearPassword(req, userData.getPassword());
			                }
			            }
			            if(password != null ){
			                newCert = registerReissueOrRecover(false,true, result, userData,password, cert.getPublicKey(), null);
			                if(newCert != null){
			                    KeyBindingAbstractType keyBinding = getResponseValues(req.getReissueKeyBinding(), newCert, false, true);
			                    result.getKeyBinding().add((KeyBindingType) keyBinding);
			                }
			            }
			        }
			    }
			}
		}
		if (log.isDebugEnabled()) {
			log.debug("getResponse resultMajor="+resultMajor+" resultMinor="+resultMinor+" isCertValid="+isCertValid+" userData=null?"+(userData==null)+" password==null?"+(password==null)+" newCert==null?"+(newCert==null));
		}
		if(resultMajor == null){ 
			resultMajor = XKMSConstants.RESULTMAJOR_SUCCESS;
		}
		setResult(result);		
		return result;
	}

    /**
     * Method that sets the users status to 'new' and a 
     * default password
     * @param the userdata of the user
     * @return the new password or null of operation failed.
     */
	private String setUserStatusToNew(EndEntityInformation userdata) {
		String retval = null;
		try {
			IPasswordGenerator passwordGenerator = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS);
			String password= passwordGenerator.getNewPassword(8, 8);

			userdata.setStatus(EndEntityConstants.STATUS_NEW);
			userdata.setPassword(password);

			endEntityManagementSession.changeUser(raAdmin, userdata, true);
			retval = password;
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage("xkms.errorsettinguserstatus", userdata.getUsername()),e);			
		}
		return retval;
	}
}
