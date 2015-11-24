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

/**
 * Local interface for OcspResponseGeneratorSession
 * 
 * @version $Id$
 */
@Local
public interface OcspResponseGeneratorSessionLocal extends OcspResponseGeneratorSession {



    void initTimers();

    /** One-time load and conversion of configured keystores to CryptoTokens and OcspKeyBindings */
    void adhocUpgradeFromPre60(char[] activationPassword);

    String healthCheck();

    /** @see org.cesecore.certificates.ocsp.cache.OcspRequestSignerStatusCache#flush() */
    void clearOcspRequestSignerRevocationStatusCache();    
}
