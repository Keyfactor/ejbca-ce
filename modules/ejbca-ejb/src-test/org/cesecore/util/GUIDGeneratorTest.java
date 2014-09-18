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
package org.cesecore.util;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.HashMap;

import org.junit.Test;


/**
 * Tests generation of GUIds, make sure there are no collisions very easily at least.
 *
 * @version $Id$
 */
public class GUIDGeneratorTest {

    @Test
    public void testGenerateGUIDs() throws Exception {
        HashMap<String, String> map = new HashMap<String, String>(500000);
        String guid;
        for (int j = 1; j < 500001; j++) {
            // Ensure we don't generate all GUIDs within the same millisecond, so pause 1ms for every 1000 GUIDs generated.
            // This should be more "real world", as we will probably not add more than 1000 records to a DB during 1 single millisecond
            if (j % 1000 == 0) {
                //log.info("Generated "+j+" GUIDs so far, sleeping for 1ms.");
                Thread.sleep(1);
            }
            guid = GUIDGenerator.generateGUID(this);
            assertNotNull("Generated GUID should not be null", guid);
            if (map.put(guid, guid) != null) {
                //                    log.warn("Duplicate guids produced: " + hex);
                //                    log.warn("Number of guids produced before duplicate: "+j);
                fail("Duplicate serno produced after "+j+" guids: "+guid);
            }
        }
    }

}
