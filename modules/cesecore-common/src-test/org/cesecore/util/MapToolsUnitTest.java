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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;

/**
 * Unit tests of MapTools.
 * @version $Id$
 */
public class MapToolsUnitTest {

    @Test
    public void sortLinkedHashMap() {
        final LinkedHashMap<Integer,String> map = new LinkedHashMap<>();
        map.put(3, "b");
        map.put(4, "A");
        map.put(1, "A");
        map.put(2, "C");
        final Map<Integer,String> savedCopy = new HashMap<>(map);
        MapTools.sortLinkedHashMap(map, String.CASE_INSENSITIVE_ORDER);
        assertEquals("Map contents should not change after sorting", savedCopy, map);
        final Iterator<Integer> iter = map.keySet().iterator();
        assertEquals("Entry 1.", Integer.valueOf(4), iter.next()); // "A"
        assertEquals("Entry 2.", Integer.valueOf(1), iter.next()); // "A"
        assertEquals("Entry 3.", Integer.valueOf(3), iter.next()); // "b"
        assertEquals("Entry 4.", Integer.valueOf(2), iter.next()); // "C"
        assertFalse("Should have reached end.", iter.hasNext());
    }

}
