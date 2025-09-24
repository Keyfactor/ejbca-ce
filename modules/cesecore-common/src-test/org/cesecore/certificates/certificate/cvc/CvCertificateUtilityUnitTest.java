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
package org.cesecore.certificates.certificate.cvc;

import org.junit.Test;

import static org.junit.Assert.*;

public class CvCertificateUtilityUnitTest {

    @Test
    public void escapeMnemonicAlphabetic() {
        assertEquals("Alphabet string should not be changed", "John Doe", CvCertificateUtility.escapeMnemonic("John Doe"));

    }

    @Test
    public void escapeMnemonicPlusMark() {
        assertEquals("Plus should be escaped", "abc\\+cba", CvCertificateUtility.escapeMnemonic("abc+cba"));
    }

    @Test
    public void escapeMnemonicEqualMark() {
        assertEquals("Equal mark should be escaped", "abc\\=\\=", CvCertificateUtility.escapeMnemonic("abc\\=="));
    }

    @Test
    public void escapeMnemonicEqualAndPlusMark() {
        assertEquals("Equal and plus marks should be escaped", "abc\\+\\=", CvCertificateUtility.escapeMnemonic("abc+\\="));
    }
}