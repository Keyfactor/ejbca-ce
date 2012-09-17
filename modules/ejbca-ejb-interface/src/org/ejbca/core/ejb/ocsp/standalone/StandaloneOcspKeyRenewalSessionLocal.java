/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ocsp.standalone;

import javax.ejb.Local;

import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;

/**
 * @version $Id$
 *
 */
@Local
public interface StandaloneOcspKeyRenewalSessionLocal {

    static final String RENEW_ALL_KEYS = "all";
    
    /**
     * This method causes the standalone OCSP responder to renew its keystores. 
     * 
     * @param signerSubjectDN subject DN of the signing key to be renewed. The string "all" (as represented by the constant 
     * TokenAndChainCache.RENEW_ALL_KEYS) will result 
     * 
     */
    void renewKeyStores(String signerSubjectDN);
    

    void setEjbcaWs(EjbcaWS ejbcaWS);

}
