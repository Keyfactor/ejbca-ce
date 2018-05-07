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

package org.ejbca.core.protocol.ws.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.ejbca.core.protocol.ws.client.gen.KeyValuePair;
import org.junit.Test;

/**
 * Tests RevokeCertWithMetadataCommand parameter handling.
 * 
 * @version $Id: RevokeCertWithMetadataCommandTest.java 22930 2016-03-04 14:02:35Z tarmo_r_helmes $
 */
public class RevokeCertWithMetadataCommandTest {
    
    @Test()
    public void testRevokeCertWithNoMetadataParameters() throws Exception {
        String[] args = new String[3];
        args[0] = "revokecertwithmetadata";
        args[1] = "CN=CA1";
        args[2] = "63706289784032807";

        RevokeCertWithMetadataCommand command = new RevokeCertWithMetadataCommand(args);
        List<KeyValuePair> parsedResult = command.parseInputArgs();
        assertNotNull(parsedResult);
        assertEquals(0, parsedResult.size());
    }

    @Test()
    public void testRevokeCertWithMetadataParameters() throws Exception {
        String[] args = new String[7];
        args[0] = "revokecertwithmetadata";
        args[1] = "CN=CA1";
        args[2] = "63706289784032807";

        args[3] = "reason=REV_SUPERSEDED";
        args[4] = "revocationdate=2012-06-07T23:55:59+02:00";
        args[5] = "certificateProfileId=12";
        args[6] = "something=123";

        RevokeCertWithMetadataCommand command = new RevokeCertWithMetadataCommand(args);
        List<KeyValuePair> parsedResult = command.parseInputArgs();
        assertEquals(4, parsedResult.size());

        assertEquals("reason", parsedResult.get(0).getKey());
        assertEquals("4", parsedResult.get(0).getValue());

        assertEquals("revocationdate", parsedResult.get(1).getKey());
        assertEquals("2012-06-07T23:55:59+02:00", parsedResult.get(1).getValue());

        assertEquals("certificateProfileId", parsedResult.get(2).getKey());
        assertEquals("12", parsedResult.get(2).getValue());

        assertEquals("something", parsedResult.get(3).getKey());
        assertEquals("123", parsedResult.get(3).getValue());
    }
}
