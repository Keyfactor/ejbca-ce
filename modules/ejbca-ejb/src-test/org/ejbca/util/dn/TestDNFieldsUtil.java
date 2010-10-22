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

package org.ejbca.util.dn;

import junit.framework.TestCase;

/**
 * @author primelars
 * @version $Id$
 *
 */
public class TestDNFieldsUtil extends TestCase {
    final private static String trickyValue1=" 10/2=5; 2 backs and a comma\\\\\\\\\\, 8/2=4 2 backs\\\\\\\\";// last comma is end of value since it is a even number (4) of \ before
    final private static String trickyValue2="\\,";// a single comma
    final private static String trickyValue3="\\\\\\\\\\\\\\,";// 3 backs and a comma
    final private static String trickyValue4="\\\\\\\\\\\\";// 3 backs
    final private static String trickyValue5="\\,\\\\\\\\\\\\\\,";// comma 3 backs comma
    final private static String trickyValue6="\\,\\\\\\\\\\\\";// comma 3 backs
    final private static String trickyValue7="\\,\\,\\,\\,\\,\\,";// 6 commas
    final private static String trickyValue8="\\\\\\,\\,\\,\\\\\\,\\,\\,\\\\";// 1 back, 3 commas, 1 back, 3 commas, 1 back
    final private static String key1 = "key1=";
    final private static String key2 = "key2=";
    final private static String c = ",";
    final private static String cKey1 = c+key1;
    final private static String cKey2 = c+key2;
    final private static String empty1 = key1+c;
    final private static String empty2 = key2+c;
    final private static String originalDN = key2+trickyValue4+c+empty1+empty2+empty1+empty1+key1+trickyValue1+c+empty1+key2+trickyValue5+c+empty1+empty2+key1+trickyValue2+cKey2+trickyValue6+c+empty1+key2+trickyValue7+cKey1+trickyValue3+c+empty1+empty2+empty1+key2+trickyValue8+c+empty1+empty2+empty2+empty1+empty1+empty2+empty1+key2;
    final private static String trailingSpacesRemovedDN = key2+trickyValue4+c+empty1+empty2+empty1+empty1+key1+trickyValue1+c+empty1+key2+trickyValue5+c+empty1+empty2+key1+trickyValue2+cKey2+trickyValue6+c+empty1+key2+trickyValue7+cKey1+trickyValue3+c+empty2+key2+trickyValue8;
    final private static String allSpacesRemovedDN = key2+trickyValue4+cKey1+trickyValue1+cKey2+trickyValue5+cKey1+trickyValue2+cKey2+trickyValue6+cKey2+trickyValue7+cKey1+trickyValue3+cKey2+trickyValue8;
    public void test01removeAllEmpties() throws Exception {
        assertEquals( allSpacesRemovedDN, DNFieldsUtil.removeAllEmpties(originalDN) );
    }
    public void test02removeTrailingEmpties() {
        assertEquals( trailingSpacesRemovedDN, DNFieldsUtil.removeTrailingEmpties(originalDN) );
    }
}
