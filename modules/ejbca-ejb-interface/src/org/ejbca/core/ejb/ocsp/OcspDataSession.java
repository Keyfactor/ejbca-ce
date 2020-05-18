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

import java.util.List;

import org.cesecore.oscp.OcspResponseData;

/**
 * 
 * @version $Id: OcspDataSession.java 35000 2020-05-07 14:32:13Z aminkh $
 *
 */
public interface OcspDataSession {
    
    /**
     * Returns the list of OCSP data corresponding to the caId
     * @param caId
     * @return a list of OCSP data for the caId, empty list if no such data.
     */
    List<OcspResponseData> findOcspDataByCaId(final Integer caId);

    /**
     * Returns the list of OCSP data corresponding to the serialNumber
     * @param serialNumber
     * @return a list of OCSP data for the serialNubmer, empty list if no such data.
     */
    List<OcspResponseData> findOcspDataBySerialNumber(final String serialNumber);
    
    /**
     * Returns the OCSP response with the latest 'nextUpdate' given CA and serial number.
     * @param caId of the CA which signed the OCSP response
     * @param serialNumber of the certificate which the OCSP response represents
     * @return OCSP data for the caId and serialNubmer, null if no such data.
     */
    OcspResponseData findOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber);
    
    /**
     * Deletes all the OCSP data from table corresponding to caId.
     * @param caId
     */
    void deleteOcspDataByCaId(final Integer caId);
    
    /**
     * Returns the OCSP response corresponding to the given id 
     * 
     * @param id the unique id for the OCSP response data 
     * @return OCSP response data or null if id could not be found.
     */
    OcspResponseData findOcspDataById(final String id);
    
    /**
     * Returns a list of distinct serial numbers of the responses expired at or before the given
     * expirationDate. Expiry date is determined by the 'nextUpdate' field of the stored OCSP response.
     * 
     * @param caId of the CA which signed the OCSP response
     * @param expirationDate date before OCSP response expires.
     * @param maxNumberOfResults Maximum number of results for this query.
     * @param offset Start offset for this query.
     * @return Serial numbers of the expired responses.
     */
    List<String> findExpiringOcpsData(Integer caId, long expirationDate, int maxNumberOfResults, int offset);
}
