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
import org.cesecore.oscp.ResponsePK;

/**
 * Local interface for OcspDataSession.
 * 
 * @version $Id$
 *
 */
@Local
public interface OcspDataSessionLocal extends OcspDataSession {
    
    void storeOcspData(final OcspResponseData ocspResponseData);
    
    OcspResponseData fetchOcspData(final ResponsePK key);
    
    byte[] fetchOcspResponse(final ResponsePK key);

}
