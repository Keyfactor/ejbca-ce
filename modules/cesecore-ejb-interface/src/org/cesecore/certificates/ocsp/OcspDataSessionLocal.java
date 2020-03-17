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
 * @version $Id$
 *
 */
@Local
public interface OcspDataSessionLocal extends OcspDataSession {
    
    void storeOcspData(final OcspResponseData ocspResponseData);
    
    List<OcspResponseData> findOcspDataByCaId(final Integer caId);

    List<OcspResponseData> findOcspDataBySerialNumber(final String serialNumber);
    
    List<OcspResponseData> findOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber);
    
    void deleteOcspDataByCaId(final Integer caId);
    
    void deleteOcspDataBySerialNumber(final String serialNumber);
    
    void deleteOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber);
    
}
