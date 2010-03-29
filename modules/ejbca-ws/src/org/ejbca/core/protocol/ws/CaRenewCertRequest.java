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
import java.util.List;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;

/** Class implementing the WS API call for caRenewCertRequest.
 * 
 * @version $Id$
 */
public class CaRenewCertRequest {

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
	 */
	public static byte[] caRenewCertRequest(EjbcaWSHelper ejbhelper, Admin admin, String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepwd) 
	throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CertPathValidatorException {
		byte[] ret = null;		
		try {
			CAInfo cainfo = ejbhelper.getCAAdminSession().getCAInfo(admin, caname);
			if (cainfo != null) {
				ret = ejbhelper.getCAAdminSession().makeRequest(admin, cainfo.getCAId(), cachain, regenerateKeys, usenextkey, activatekey, keystorepwd);				
			}
		} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, null);
		}
		return ret;
	}

}
