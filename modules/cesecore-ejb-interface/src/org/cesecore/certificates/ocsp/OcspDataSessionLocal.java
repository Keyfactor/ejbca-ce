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
     * Saves OCSP data in the table. This method runs asynchronous.
     * @param ocspResponseData
     */
    void storeOcspData(final OcspResponseData ocspResponseData);
    
    /**
     * Deletes all the OCSP data from table corresponding to serialNumber.
     * @param serialNumber of the certificate which the OCSP response represents
     */
    void deleteOcspDataBySerialNumber(final String serialNumber);
    
    /**
     * Deletes all the OCSP data from table corresponding to caId and serialNumber.
     * @param caId
     * @param serialNumber of the certificate which the OCSP response represents
     */
    void deleteOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber);
    
}
