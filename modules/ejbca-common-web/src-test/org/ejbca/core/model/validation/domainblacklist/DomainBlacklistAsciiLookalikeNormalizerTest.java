package org.ejbca.core.model.validation.domainblacklist;


import org.junit.BeforeClass;
import org.junit.Test;

import java.net.IDN;
import java.text.ParseException;

import static org.junit.Assert.assertEquals;

/**
 * Tests DomainBlacklistAsciiLookalikeNormalizer functions.
 *
 * @version $Id$
 */
public class DomainBlacklistAsciiLookalikeNormalizerTest  {
    private static DomainBlacklistAsciiLookalikeNormalizer normalizer;

    @BeforeClass
    public static void before(){
        normalizer = new DomainBlacklistAsciiLookalikeNormalizer();
    }

    @Test
    public void testNormalize() throws Exception {
        String result = normalizer.normalize("go091e.com");
        assertEquals("Expected normalized string", "google.com", result);

    }

    @Test
    public void testNormalizeLetterCombination() throws Exception {
        String result = normalizer.normalize("clcirnfivv5");
        assertEquals("Expected normalized string", "damaws", result);

    }

    @Test
    public void testNormalizePunicode() throws ParseException {
        String punycode = IDN.toASCII("котикg009levv");
        String punycodeNormalized = normalizer.normalize(punycode);

        String normilizedUnicode = IDN.toUnicode(punycodeNormalized);
        assertEquals("Expexted normalized punicode", "xn--googlevv-28gtb0c0c", punycodeNormalized);
        assertEquals("Expexted normalized unicode", "котикgooglevv", normilizedUnicode);
    }


}