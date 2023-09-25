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
package org.ejbca.config;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AvailableProtocolsConfigurationTest {

    /**
     * Verifies protocol path lookup.
     * Path is the same in EE and CE! See ECA-11827
     */
    @Test
    public void testGetContextPathByName() {
        
        String fullPaths = "/ejbca/ejbca-rest-api/v1/ca<br/>" + "/ejbca/ejbca-rest-api/v1/certificate";
        
        assertEquals("Unexpected protocol path", fullPaths,
                AvailableProtocolsConfiguration.AvailableProtocols.getContextPathByName(AvailableProtocolsConfiguration.AvailableProtocols.REST_CERTIFICATE_MANAGEMENT.getName()));
    }
}
