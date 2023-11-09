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
package org.ejbca.core.ejb.ocsp;

import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.certificate.BaseCertificateData;

import javax.ejb.Local;

@Local
public interface PreSigningOcspResponseSessionLocal {

	/**
	 * Returns the OCSP response with the latest 'nextUpdate' given CA and serial number.
	 *
	 * @param caId of the CA which signed the OCSP response
	 * @param serialNumber of the certificate which the OCSP response represents
	 * @return OCSP data for the caId and serialNubmer, null if no such data.
	 */
	boolean isOcspExists(final Integer caId, final String serialNumber);

	/**
	 * Deletes all the OCSP data from table corresponding to caId and serialNumber.
	 *
	 * @param caId certificate authority identifier.
	 * @param serialNumber of the certificate which the OCSP response represents
	 */
	void deleteOcspDataByCaIdSerialNumber(final int caId, final String serialNumber);

	/**
	 * Pre-signs an OCSP response having a certificate chain passed.
	 *
	 * @param ca the Certificate Authority.
	 * @param certData base certificate information.
	 */
	void preSignOcspResponse(CA ca, BaseCertificateData certData);

}
