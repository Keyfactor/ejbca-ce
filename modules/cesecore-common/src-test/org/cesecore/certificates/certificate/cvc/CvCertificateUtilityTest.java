package org.cesecore.certificates.certificate.cvc;

import org.junit.Test;

import static org.junit.Assert.*;

public class CvCertificateUtilityTest {

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