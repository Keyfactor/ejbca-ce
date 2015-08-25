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
package org.ejbca.core.model.ra.raadmin;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.junit.Test;

/**
 * Unit tests for the EndEntityProfile class.
 * 
 * @version $Id$
 *
 */
public class EndEntityProfileTest {

    @Test
    public void testEndEntityProfileDiff() {
        EndEntityProfile foo = new EndEntityProfile();
        EndEntityProfile bar = new EndEntityProfile();
        bar.addField(DnComponents.ORGANIZATIONALUNIT);
        Map<Object, Object> diff = foo.diff(bar);
        assertFalse(diff.isEmpty());
    }
    
    /**
     * Tests the validation system, and the regex validator in particular.
     */
    @Test
    public void testRegexValidation() throws EndEntityFieldValidatorException {
        // The regex validator ignored the dn component, so that can be set to anything
        EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "[0-9-]*");
        EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "[0-9-]*@([a-z.-]+|localhost)");
        try {
            EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "*");
            fail("should throw EndEntityFieldValidatorException on invalid regex");
        } catch (EndEntityFieldValidatorException e) {
            // NOPMD should throw
        }
        
        // Test some values
        EndEntityValidationHelper.checkValue(DnComponents.COMMONNAME, makeRegexValidator("[0-9]*"), "123");
        try {
            EndEntityValidationHelper.checkValue(DnComponents.COMMONNAME, makeRegexValidator("[0-9]*"), "abc");
           fail("should throw EndEntityFieldValidatorException on invalid value");
        } catch (EndEntityFieldValidatorException e) {
            // NOPMD should throw
        }
    }
    
    private static Map<String,Serializable> makeRegexValidator(final String regex) {
        final Map<String,Serializable> map = new LinkedHashMap<String,Serializable>();
        map.put(RegexFieldValidator.class.getName(), regex);
        return map;
    }
    
}
