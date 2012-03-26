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
package org.cesecore.certificates.ocsp.standalone;

import java.util.Collection;

import javax.ejb.Local;

import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;

/**  
 * @version $Id$
 *
 */
@Local
public interface StandaloneOcspResponseGeneratorSessionLocal extends StandAloneOcspResponseGeneratorSession, OcspResponseGeneratorSessionLocal {

    /**
     * 
     * @return the contents of the token and chain cache.
     */
    Collection<CryptoTokenAndChain> getCacheValues();
    
}
