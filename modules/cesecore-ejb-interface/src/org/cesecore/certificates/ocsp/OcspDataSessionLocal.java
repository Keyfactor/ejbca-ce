/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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

import java.util.List;

import javax.ejb.Local;

import org.cesecore.oscp.OcspResponseData;

/**
 * Local interface for OcspDataSession.
 * 
 * Note that in some implementations of JPA the getResultList returns null in case
 * no data found in database (recent and more accurate implementations return empty list). 
 * To be on the safe side it is advisable to program defensively and do a null check when 
 * dealing with the results returned from methods of this class which use getResultList!
 * (Check {@link #OcspDataSessionBean} for more details). 
 * 
 * @version $Id$
 *
 */
@Local
public interface OcspDataSessionLocal extends OcspDataSession {
    
    /**
     * Saves OCSP data in the table
     * @param ocspResponseData
     */
    void storeOcspData(final OcspResponseData ocspResponseData);
    
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
     * Returns all the OCSP data matching the caId and serialNumber as a list.
     * @param caId
     * @param serialNumber
     * @return a list of OCSP data for the caId and serialNubmer, empty list if no such data.
     */
    List<OcspResponseData> findOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber);
    
    /**
     * Deletes all the OCSP data from table corresponding to caId.
     * @param caId
     */
    void deleteOcspDataByCaId(final Integer caId);
    
    /**
     * Deletes all the OCSP data from table corresponding to serialNumber.
     * @param serialNumber
     */
    void deleteOcspDataBySerialNumber(final String serialNumber);
    
    /**
     * Deletes all the OCSP data from table corresponding to caId and serialNumber.
     * @param caId
     * @param serialNumber
     */
    void deleteOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber);
    
}
