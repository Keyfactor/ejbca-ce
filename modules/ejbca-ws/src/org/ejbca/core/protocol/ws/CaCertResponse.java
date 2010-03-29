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
package org.ejbca.core.protocol.ws;

import java.rmi.RemoteException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.List;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.util.CertTools;

/** Class implementing the WS API call for caRenewCertRequest.
 * 
 * @version $Id$
 */
public class CaCertResponse {

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
	 */
	public static void caCertResponse(EjbcaWSHelper ejbhelper, Admin admin, String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) 
	throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CertPathValidatorException {
		try {
			CAInfo cainfo = ejbhelper.getCAAdminSession().getCAInfo(admin, caname);
			// create response messages, for CVC certificates we use a regular X509ResponseMessage
			X509ResponseMessage msg = new X509ResponseMessage();
			msg.setCertificate(CertTools.getCertfromByteArray(cert));
			ejbhelper.getCAAdminSession().receiveResponse(admin, cainfo.getCAId(), msg, cachain, keystorepwd);
		} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, null);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, null);
		}
	}

}
