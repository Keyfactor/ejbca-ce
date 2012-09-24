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
package org.ejbca.core.protocol.ocsp;

import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.protocol.ocsp.standalone.OcspKeyRenewalProxySessionRemote;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class OcspKeyRenewalTest {
    
    OcspKeyRenewalProxySessionRemote ocspKeyRenewalProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(OcspKeyRenewalProxySessionRemote.class);
    
    
    @Test
    public void testKeyRenewal() {
        ocspKeyRenewalProxySession.renewKeyStores("CN=ocspTestSigner");
    }
   
}
