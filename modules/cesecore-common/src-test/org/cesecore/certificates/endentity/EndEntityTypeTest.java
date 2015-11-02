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
package org.cesecore.certificates.endentity;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Unit tests for the {@link EndEntityType} class and the {@link EndEntityTypes} enum.
 * 
 * @version $Id$
 *
 */
public class EndEntityTypeTest {

    @Test
    public void testIsTypeBasic() {
        //Basic test.
        EndEntityType basicType = new EndEntityType(EndEntityTypes.ADMINISTRATOR);
        assertTrue(basicType.isType(EndEntityTypes.ADMINISTRATOR));
        assertFalse(basicType.isType(EndEntityTypes.ENDUSER));
        assertFalse(basicType.isType(EndEntityTypes.INVALID));
    }
    
    @Test
    public void testIsTypeComplex() {
        //Complex test
        EndEntityType complexType = new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR);
        assertFalse(complexType.isType(EndEntityTypes.ENDUSER));
        assertFalse(complexType.isType(EndEntityTypes.ADMINISTRATOR));
    }
    
    @Test
    public void testAddToType() {
        EndEntityType type = new EndEntityType();
        if((type.getHexValue() & EndEntityTypes.ENDUSER.hexValue()) == EndEntityTypes.ENDUSER.hexValue()) {
            throw new RuntimeException("Type shouldn't contain ENDUSER to begin with.");
        }
        type.addType(EndEntityTypes.ENDUSER);
        assertTrue((type.getHexValue() & EndEntityTypes.ENDUSER.hexValue()) == EndEntityTypes.ENDUSER.hexValue()); 
        type.addType(EndEntityTypes.ADMINISTRATOR);
        assertTrue((type.getHexValue() & EndEntityTypes.ADMINISTRATOR.hexValue()) == EndEntityTypes.ADMINISTRATOR.hexValue()); 
    }
    
    @Test
    public void testContains() {
        EndEntityType type = new EndEntityType(EndEntityTypes.INVALID);
        if(type.contains(EndEntityTypes.ENDUSER)) {
            throw new RuntimeException("Type shouldn't contain ENDUSER to begin with.");
        }
        type.addType(EndEntityTypes.ENDUSER);
        assertTrue(type.contains(EndEntityTypes.ENDUSER));   
        //Since EndEntityTypes.INVALID is 0x0, it can always be considered "contained". 
        assertTrue(type.contains(EndEntityTypes.INVALID));
    }
    
    @Test 
    public void testRemoveType() {
        EndEntityType type = new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.PRINT);
        if((type.getHexValue() & EndEntityTypes.ENDUSER.hexValue()) != EndEntityTypes.ENDUSER.hexValue()) {
            throw new RuntimeException("Type doesn't contain ENDUSER, can't continue");
        }
        type.removeType(EndEntityTypes.ENDUSER);
        assertTrue("EndEntityTypes.ENDUSER wasn't removed properly", (type.getHexValue() & EndEntityTypes.ENDUSER.hexValue()) != EndEntityTypes.ENDUSER.hexValue());
        try {
            type.removeType(EndEntityTypes.ADMINISTRATOR);
        } catch(Exception e) {
            fail("Unexistant type should have been removed safely.");
        }
        assertTrue((type.getHexValue() & EndEntityTypes.PRINT.hexValue()) == EndEntityTypes.PRINT.hexValue());
    }
}
