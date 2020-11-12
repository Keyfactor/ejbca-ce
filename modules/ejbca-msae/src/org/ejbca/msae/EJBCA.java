/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.common.CertificateHelper;

public class EJBCA {
	private WebServiceConnection ws;

	public EJBCA(WebServiceConnection ws) {
		this.ws = ws;
	}

	public byte[] issuePKCS7Certificate(UserDataVOWS userDataVOWS, String pkcs10request) throws EnrollmentException {
		CertificateResponse response;
		
		try {
			response = ws.certificateRequest(userDataVOWS,
					pkcs10request,
					CertificateHelper.CERT_REQ_TYPE_PKCS10, 
					null,
					CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN);
		} catch (Exception e) {
			throw new EnrollmentException("Error getting certificate: " + e.getMessage());
		}

		return response.getRawData();
	}
}