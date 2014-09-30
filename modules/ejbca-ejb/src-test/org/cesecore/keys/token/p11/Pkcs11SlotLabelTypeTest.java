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
package org.cesecore.keys.token.p11;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class Pkcs11SlotLabelTypeTest {

    @Test
    public void testNumberTypeValidator() {
        Pkcs11SlotLabelType type = Pkcs11SlotLabelType.SLOT_NUMBER;
        assertTrue("Validator did not validate a number.", type.validate("4711"));
        assertFalse("Validator falsely validated a label", type.validate("foo"));
        assertFalse("Validator falsely validated an index", type.validate("i7"));
    }
    
    @Test
    public void testIndexTypeValidator() {
        Pkcs11SlotLabelType type = Pkcs11SlotLabelType.SLOT_INDEX;
        assertFalse("Validator falsely validated a number.", type.validate("4711"));
        assertFalse("Validator falsely validated a label", type.validate("foo"));
        assertTrue("Validator did not correctly validate an index", type.validate("i7"));
    }
    
    @Test
    public void testLabelTypeValidator() {
        Pkcs11SlotLabelType type = Pkcs11SlotLabelType.SLOT_LABEL;
        assertTrue("Validator did not correctly validate a label", type.validate("4711"));
        assertTrue("Validator did not correctly validate a label", type.validate("foo"));
        assertTrue("Validator did not correctly validate a label", type.validate("i7"));
    }

    @Test
    public void testLongLabelValidation() {
        assertFalse("Label of >32 characters validated.",
                Pkcs11SlotLabelType.SLOT_LABEL.validate("YeahbutIcantusethewordsoberbecausethatsatermfromthosepeopleandIhavecleansedmyself"));
    }
    
}
