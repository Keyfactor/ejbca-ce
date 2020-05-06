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
    int deleteOcspDataByCaId(final Integer caId);

}
