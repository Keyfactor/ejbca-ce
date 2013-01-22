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

import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import org.cesecore.util.GUIDGenerator;
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
            guid = GUIDGenerator.generateGUID(this);
            if (map.put(guid, guid) != null) {
                //                    log.warn("Duplicate guids produced: " + hex);
                //                    log.warn("Number of guids produced before duplicate: "+j);
                assertTrue("Duplicate serno produced after "+j+" guids: "+guid, false);
            }
        }
    }

}
