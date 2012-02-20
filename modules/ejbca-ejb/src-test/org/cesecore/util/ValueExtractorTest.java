/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import static org.junit.Assert.assertEquals;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.junit.Test;

/**
 * Tests value extraction in jdbc utility class
 * 
 * @version $Id$
 */
public class ValueExtractorTest {

    @Test
    public void testValueExtractorSimple() throws Exception {
        Integer integer = Integer.valueOf(1);
        BigInteger bi = new BigInteger("2");
        BigDecimal bd = new BigDecimal(3);
        assertEquals(1, ValueExtractor.extractIntValue(integer));
        assertEquals(2, ValueExtractor.extractIntValue(bi));
        assertEquals(3, ValueExtractor.extractIntValue(bd));
        assertEquals(1, ValueExtractor.extractLongValue(integer));
        assertEquals(2, ValueExtractor.extractLongValue(bi));
        assertEquals(3, ValueExtractor.extractLongValue(bd));
    }

    @Test
    public void testValueExtractorArray() throws Exception {
        Integer intval = Integer.valueOf(1);
        BigInteger birow = new BigInteger("2");
        BigDecimal bdval = new BigDecimal(3);
        BigDecimal bdrow = new BigDecimal(4);
        
        Object[] db2 = new Object[2];
        db2[0] = birow;
        db2[1] = intval;
        
        Object[] oracle = new Object[2];
        oracle[0] = bdval;
        oracle[1] = bdrow;
        
        assertEquals(1, ValueExtractor.extractIntValue(db2));
        assertEquals(3, ValueExtractor.extractIntValue(oracle));
        assertEquals(1, ValueExtractor.extractLongValue(db2));
        assertEquals(3, ValueExtractor.extractLongValue(oracle));        
    }

}
