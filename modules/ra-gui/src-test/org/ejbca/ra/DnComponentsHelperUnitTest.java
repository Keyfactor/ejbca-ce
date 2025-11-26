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
package org.ejbca.ra;

import com.keyfactor.util.certificate.DnComponents;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * Unit tests for the DnComponentsHelper.
 *
 * @author Marcus Lundblad
 */
public class DnComponentsHelperUnitTest {

    /**
     * Test parsing SAN field name with name UNIFORMRESOURCEIDENTIFIER, should give the same
     * ID as UNIFORMRESOURCEID (23).
     *
     * @throws Exception 
     */
    @Test
    public void testGetDnIdFromTypeAndNameUNIFORMRESOURCEIDENTIFIER() throws Exception {
        // given
        final int expectedDnId = 23;
        final String name = "UNIFORMRESOURCEIDENTIFIER";

        // then
        testGetDnIdFromTypeAndNameInternal(DnComponentsHelper.RequestFieldType.AN,
                                           name, expectedDnId);
    }

    /**
     * Test parsing SAN field name with name UNIFORMRESOURCEID.
     *
     * @throws Exception 
     */
    @Test
    public void testGetDnIdFromTypeAndNameUNIFORMRESOURCEID() throws Exception {
        // given
        final int expectedDnId = 23;
        final String name = "UNIFORMRESOURCEID";

        testGetDnIdFromTypeAndNameInternal(DnComponentsHelper.RequestFieldType.AN,
                                           name, expectedDnId);
    }

    private void testGetDnIdFromTypeAndNameInternal(final DnComponentsHelper.RequestFieldType type,
                                                    final String name,
                                                    final Integer expectedId) {
        assertEquals("DN ID", expectedId,
                     DnComponentsHelper.getDnIdFromTypeAndName(type, name));
    }

}
