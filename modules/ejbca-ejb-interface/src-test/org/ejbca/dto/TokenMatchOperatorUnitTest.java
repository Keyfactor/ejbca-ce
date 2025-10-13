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

package org.ejbca.dto;

import org.cesecore.dto.TokenMatchOperator;
import org.junit.Assert;
import org.junit.Test;

public class TokenMatchOperatorUnitTest {

    @Test
    public void testSupplierUtil() {
        var actual = TokenMatchOperator.valueOf(TokenMatchOperator.TYPE_EQUALCASE.get());
        Assert.assertEquals(
                "TokenMatchOperator.valueOf returns wrong enum instance for int "+TokenMatchOperator.TYPE_EQUALCASE.get()+".\nExpected: TYPE_EQUALCASE\nActual:   "+actual.name(),
                TokenMatchOperator.TYPE_EQUALCASE,
                actual);
    }

}
