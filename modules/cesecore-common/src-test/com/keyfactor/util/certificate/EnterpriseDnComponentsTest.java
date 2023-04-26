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
package com.keyfactor.util.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import org.junit.Test;

/**
 * Test the {@link DnComponents} class with the enterprise properties
 */
public class EnterpriseDnComponentsTest {

    @Test
    public void testEnterpriseProperties() {
        assumeTrue(DnComponents.enterpriseMappingsExist());
        assertEquals("JURISDICTIONLOCALITY=", DnComponents.getDnExtractorFieldFromDnId(103));
        assertEquals("JURISDICTIONSTATE=", DnComponents.getDnExtractorFieldFromDnId(104));
        assertEquals("JURISDICTIONCOUNTRY=", DnComponents.getDnExtractorFieldFromDnId(105));
        assertEquals("ORGANIZATIONIDENTIFIER=", DnComponents.getDnExtractorFieldFromDnId(106));
    }
    
}
