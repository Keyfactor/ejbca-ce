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
package org.ejbca.ui.admin.keys.validation;

import org.ejbca.ui.web.admin.keys.validation.ValidatorsBean;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * A unit test for ValidatorsBean.
 */
public class ValidatorsBeanUnitTest {

    @Test
    public void removePrecedingSpaces() {
        ValidatorsBean validatorsBean = new ValidatorsBean();
        validatorsBean.setNewValidatorName("  abc");
        assertEquals("All spaces at the beginning should be removed.", "abc", validatorsBean.getNewValidatorName());
    }

    @Test
    public void removeTrailingSpaces() {
        ValidatorsBean validatorsBean = new ValidatorsBean();
        validatorsBean.setNewValidatorName("abc  ");
        assertEquals("All spaces at the end should be removed.", "abc", validatorsBean.getNewValidatorName());
    }

    @Test
    public void keepSpacesInBetween() {
        ValidatorsBean validatorsBean = new ValidatorsBean();
        validatorsBean.setNewValidatorName("ab   cd");
        assertEquals("All spaces in between letters must be kept. ", "ab   cd", validatorsBean.getNewValidatorName());
    }
}
