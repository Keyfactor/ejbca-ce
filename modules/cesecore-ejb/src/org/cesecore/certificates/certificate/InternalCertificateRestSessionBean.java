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
package org.cesecore.certificates.certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import static org.cesecore.authorization.control.StandardRules.SYSTEMCONFIGURATION_VIEW;

@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class InternalCertificateRestSessionBean implements InternalCertificateRestSessionLocal {

	static final String ERROR_MESSAGE = "Unauthorized access to the resource. Token: %s. "
			+ "Only the user with the \"/system_functionality/view_systemconfiguration/\" privilege "
			+ "is allowed to perform this operation.";

	@EJB
	private CertificateDataSessionLocal certDataSession;

	@EJB
	private AuthorizationSessionLocal authorizationSession;

	@Override
	public Long getCertificateCount(AuthenticationToken adminToken, Boolean isActive) throws AuthorizationDeniedException {
		if (!authorizationSession.isAuthorized(adminToken, SYSTEMCONFIGURATION_VIEW.resource())) {
			throw new AuthorizationDeniedException(String.format(ERROR_MESSAGE, adminToken.toString()));
		}
		if (isActive != null && isActive) {
			return certDataSession.findQuantityOfTheActiveCertificates();
		}
		return certDataSession.findQuantityOfAllCertificates();
	}

}
