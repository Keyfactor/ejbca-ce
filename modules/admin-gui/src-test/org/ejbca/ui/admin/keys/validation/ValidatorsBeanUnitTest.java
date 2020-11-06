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
 *
 * @version $Id$
 */
public class ValidatorsBeanUnitTest {

    @Test
    public void testSetNewValidatorName() {
        ValidatorsBean validatorsBean = new ValidatorsBean();
        validatorsBean.setNewValidatorName(" abc  ");
        assertEquals("abc", validatorsBean.getNewValidatorName());
    }
}
