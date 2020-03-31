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

/**
 * A unit test for static configuration.
 *
 * @version $Id$
 */
public class WebConfigurationTest {

    @Test
    public void testDcBaseURI() {
        EjbcaConfigurationHolder.updateConfiguration(WebConfiguration.CONFIG_DOCBASEURI, "internal");
        assertEquals("internal", WebConfiguration.getDocBaseUri());
        EjbcaConfigurationHolder.updateConfiguration(WebConfiguration.CONFIG_DOCBASEURI, "disabled");
        assertEquals("disabled", WebConfiguration.getDocBaseUri());
        EjbcaConfigurationHolder.updateConfiguration(WebConfiguration.CONFIG_DOCBASEURI, "https://doc.primekey.com/ejbca");
        assertEquals("https://doc.primekey.com/ejbca", WebConfiguration.getDocBaseUri());
        EjbcaConfigurationHolder.updateConfiguration(WebConfiguration.CONFIG_DOCBASEURI, "https://doc.primekey.com/ejbca?foo=bar");
        assertEquals("https://doc.primekey.com/ejbca", WebConfiguration.getDocBaseUri());
        EjbcaConfigurationHolder.updateConfiguration(WebConfiguration.CONFIG_DOCBASEURI, "\"></a><script>window.alert(\"pwnd\");</script><a href=\"https://www.ejbca.org/docs");
        assertEquals("internal", WebConfiguration.getDocBaseUri());
    }
}
