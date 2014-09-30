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

import javax.ejb.FinderException;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.crl.CrlStoreSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.config.GlobalConfigurationSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.w3._2002._03.xkms_.KeyBindingAbstractType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.RevokeRequestType;
import org.w3._2002._03.xkms_.RevokeResultType;
import org.w3c.dom.Document;

/**
 * Class generating a response for a revoke call
 * 
 * @version $Id$
 */

public class RevokeResponseGenerator extends KRSSResponseGenerator {

    private EndEntityManagementSession endEntityManagementSession;
    
    public RevokeResponseGenerator(String remoteIP, RevokeRequestType req, Document requestDoc,
    		CaSession caadminsession, EndEntityAuthenticationSession authenticationSession, CertificateStoreSession certificateStoreSession, EndEntityAccessSession endEntityAccessSession,
    		EndEntityProfileSession endEntityProfileSession, KeyRecoverySession keyRecoverySession, GlobalConfigurationSession globalConfigurationSession,
    		SignSession signSession, EndEntityManagementSession endEntityManagementSession, CrlStoreSession crlSession) {
        super(remoteIP, req, requestDoc, caadminsession, authenticationSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession,
				keyRecoverySession, globalConfigurationSession, signSession, endEntityManagementSession, crlSession);
        this.endEntityManagementSession = endEntityManagementSession;
    }
	
	/**
	 * Returns a reissue response
	 */
	public RevokeResultType getResponse(boolean requestVerifies){
		RevokeResultType result = xkmsFactory.createRevokeResultType();		
		super.populateResponse(result, requestVerifies);		
		RevokeRequestType req = (RevokeRequestType) this.req;
		

		if(resultMajor == null){ 		
			if(!checkValidRespondWithRequest(req.getRespondWith(),true)){
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
			}

			if(resultMajor == null){ 
				if(resultMajor == null){ 
					X509Certificate cert = (X509Certificate) getPublicKeyInfo(req, false);
					boolean isCertValid = certIsValid(cert);
					if(isCertValid){						
						EndEntityInformation userData = findUserData(cert);
						String revocationCodeId = getRevocationCodeFromUserData(userData);
						if(userData != null && revocationCodeId != null){
							String revokeCode = getRevocationCode(req);
							if(XKMSConfig.isRevocationAllowed()){
							  if(revokeCode != null ){
								X509Certificate newCert = revoke(revokeCode, revocationCodeId, cert);
								if(newCert != null && req.getRespondWith().size() > 0){
									KeyBindingAbstractType keyBinding = getResponseValues(req.getRevokeKeyBinding(), newCert, true, false);
									result.getKeyBinding().add((KeyBindingType) keyBinding);
								}
							  }
							}else{
								resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
								resultMinor = XKMSConstants.RESULTMINOR_REFUSED;								
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
	 * Method that returns the revocation code identifier in the extended information
	 * or null if no revocation identifier exists
	 * @param userData
	 * @return
	 */
	private String getRevocationCodeFromUserData(EndEntityInformation userData) {
		String retval = null;
		if(userData != null && userData.getExtendedinformation() != null 
		   && userData.getExtendedinformation().getRevocationCodeIdentifier() != null){
			retval = userData.getExtendedinformation().getRevocationCodeIdentifier();
		}
		
		if(retval == null){
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_NOAUTHENTICATION;
		}
		
		return retval;
	}

	private X509Certificate revoke(String password, String revocationCode,  X509Certificate cert) {
		X509Certificate retval = null;
		// Check the password
				
		if(revocationCode.equals(password)){				
			// revoke cert
			try {								
			    endEntityManagementSession.revokeCert(raAdmin, cert.getSerialNumber(), CertTools.getIssuerDN(cert), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
				retval = cert;
			} catch (WaitingForApprovalException e) {
				// The request has been sent for approval. -> Only part of the information requested could be provided.
				resultMajor = XKMSConstants.RESULTMAJOR_SUCCESS;
				resultMinor = XKMSConstants.RESULTMINOR_INCOMPLETE;
				retval = cert;
			} catch (ApprovalException e) {
				// Approval request already exists. -> The receiver is currently refusing certain requests for unspecified reasons.
				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
				resultMinor = XKMSConstants.RESULTMINOR_REFUSED;
			} catch (AuthorizationDeniedException e) {
				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
			} catch (AlreadyRevokedException e) {
				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
			} catch (FinderException e) {
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_NOMATCH;
			}
		}else{
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_NOAUTHENTICATION;			
		}
		return retval;
	}
}
