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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class InternalCertificateRestSessionBean implements InternalCertificateRestSessionLocal {

	@EJB
	private CertificateDataSessionLocal certDataSession;

	@Override
	public Long getCertificateCount(Boolean isActive) {
		if (isActive != null && isActive) {
			return certDataSession.findQuantityOfTheActiveCertificates();
		}
		return certDataSession.findQuantityOfAllCertificates();
	}
}
