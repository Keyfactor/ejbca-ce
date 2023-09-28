/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
