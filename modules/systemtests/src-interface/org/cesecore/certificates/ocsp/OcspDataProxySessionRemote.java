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
package org.cesecore.certificates.ocsp;

import javax.ejb.Remote;

import org.cesecore.oscp.OcspResponseData;

/**
 * @version $Id
 */
@Remote
public interface OcspDataProxySessionRemote {

    /**
     * Save OCSP data in the table. This method runs asynchronous.
     *
     * @param responseData
     */
    void storeOcspData(OcspResponseData responseData);

    /**
     * Delete all the OCSP data from table corresponding to caId.
     *
     * @param caId
     */
    void deleteOcspDataByCaId(final Integer caId);

    /**
     * Delete all the OCSP data from table corresponding to serialNumber.
     *
     * @param serialNumber of the certificate which the OCSP response represents
     */
    void deleteOcspDataBySerialNumber(final String serialNumber);

    /**
     * Delete all the OCSP data from table corresponding to caId and serialNumber.
     *
     * @param caId
     * @param serialNumber of the certificate which the OCSP response represents
     */
    void deleteOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber);

    /**
     * Delete the old OCSP data from the table, and leave only responses with the latest producedAt
     * for each serial number and given certificate authority.
     *
     * @param caId of the certificate authority.
     */
    int deleteOldOcspDataByCaId(final Integer caId);

    /**
     * Deletes all the old OCSP data from the table, and leave only responses with the latest producedAt
     * for each serial number.
     */
    int deleteOldOcspData();
}
