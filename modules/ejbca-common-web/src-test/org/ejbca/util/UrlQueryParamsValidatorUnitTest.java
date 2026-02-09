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
package org.ejbca.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

public class UrlQueryParamsValidatorUnitTest {

    private static final String[] ENCODED_FORBIDDEN_CHARACTERS = {
            "%22", // "
            "%27", // '
            "%3C", // <
            "%3E", // >
            "%5C", // \
            "%5E", // ^
            "%60", // `
            "%7B", // {
            "%7D", // }
            "%7C"  // |
    };

    /* -------------------------
     * Helper
     * ------------------------- */

    private void assertInvalid(String query) {
        assertFalse(UrlQueryParamsValidator.validateRestApiUrlQueryParams(query));
    }

    private void assertValid(String query) {
        assertTrue(UrlQueryParamsValidator.validateRestApiUrlQueryParams(query));
    }

    /* -------------------------
     * VALID CASES
     * ------------------------- */

    @Test
    public void shouldAcceptNoParam() {
        assertValid("");
        assertValid(null);
    }
    
    @Test
    public void shouldDeny() {
        assertFalse(UrlQueryParamsValidator.validateRestApiUrlQueryParams("days=50&offset=0&maxNumberOfResults=10\""));
        assertFalse(UrlQueryParamsValidator.validateRestApiUrlQueryParams("days=50&offset=0&maxNumberOfResults=10%22"));
        
        assertFalse(UrlQueryParamsValidator.validateRestApiUrlQueryParams("isActive=F\""));
        assertFalse(UrlQueryParamsValidator.validateRestApiUrlQueryParams("isActive=F%22"));
    }
    
    @Test
    public void shouldAcceptSingleParam() {
        assertValid("q=helloWorld");
    }
    
    @Test
    public void shouldRejectUmaluts() { // we have no such REST API
        String[] europeanSpecials = {
                "abcäöüÄÖÜßxyz",
                "abcéèêëàâæçîïôœùûüÿxyz",
                "abcáéíóúüñ¿¡xyz",
                "abcåäöxyz",
                "abcæøåxyz",
                "abcąćęłńóśżźxyz",
                "abcáéíóöőúüűxyz",
                "abcëïéèáíóúĳxyz"
            };
        for (String s: europeanSpecials) {
            assertInvalid("q=" + s);
        }
    }

    @Test
    public void shouldAcceptTwoParamsEncoded() {
        assertValid("q=rock%26roll1234&page=1");
    }
    
    @Test
    public void shouldRejectStrangeIntegers() {
        assertInvalid("q=rock%26roll1234&offset=+12345");
        assertInvalid("q=rock%26roll1234&offset=-12345");
    }
    
    
    @Test
    public void shouldAcceptEncodedDates() {
        assertValid("q=rock%26roll&date=2018-06-15T14%3A07%3A09Z");
    }
    
    @Test
    public void shouldAcceptNotEncodedDates() {
        assertValid("reason=KEY_COMPROMISE&date=2026-02-02T06:02:49Z");
    }
    
    @Test
    public void shouldAcceptAsterisk() {
        assertValid("q=rock%26roll&include=CA%3Aabcd%2A");
        assertValid("q=rock%26roll&include=CA%3Aabcd*");
    }
    
    @Test
    public void shouldAcceptUnderscpre() {
        assertValid("q=rock%26roll&reason=NOT_REVOKED");
    }
    
    @Test
    public void shouldAcceptMultipleParamsEncodedBoolean() {
        assertValid("q=rock%26roll&page=1&enabled=false");
        assertValid("q=rock%26roll&page=1&enabled=false&some=things#");
    }

    /* -------------------------
     * RAW FORBIDDEN CHARACTERS
     * ------------------------- */

    @Test
    public void shouldRejectRawLessThanAsFirstCharInValue() {
        assertInvalid("q=<value");
    }

    @Test
    public void shouldRejectRawGreaterThanAsLastCharInValue() {
        assertInvalid("q=value>");
    }

    @Test
    public void shouldRejectRawForbiddenCharAsFirstCharInKey() {
        assertInvalid("<q=value");
    }

    @Test
    public void shouldRejectRawForbiddenCharAsLastCharInKey() {
        assertInvalid("q>=value");
    }

    /* -------------------------
     * CONTROL CHARACTERS (\p{Cntrl})
     * ------------------------- */

    @Test
    public void shouldRejectEncodedNullByte() {
        assertInvalid("q=%00");
    }

    @Test
    public void shouldRejectEncodedNewline() {
        assertInvalid("q=%0A");
    }

    @Test
    public void shouldRejectEncodedCarriageReturnInKey() {
        assertInvalid("%0Dq=value");
    }

    /* -------------------------
     * FORBIDDEN SYMBOLS
     * "[\\p{Cntrl}\"#<>\\\\^`{}|]"
     * ------------------------- */

    @Test
    public void shouldRejectForbiddenSymbolsInValue() {
        
        for (String b : ENCODED_FORBIDDEN_CHARACTERS) {
            assertInvalid("query1=" + b);
            assertInvalid("query0=false&query1=" + b + "&query2=xyz");
            assertInvalid("query0=false&query1=" + URLDecoder.decode(b, StandardCharsets.UTF_8) + "&query2=xyz");
        }
    }

    @Test
    public void shouldRejectForbiddenSymbolsInKey() {

        for (String b : ENCODED_FORBIDDEN_CHARACTERS) {
            assertInvalid(b + "=value");
            assertInvalid("query0=false&" + b + "=value&query2=xyz");
            assertInvalid("query0=false&" + URLDecoder.decode(b, StandardCharsets.UTF_8) + "=value&query2=xyz");
        }
    }

    /* -------------------------
     * DOUBLE ENCODING
     * ------------------------- */

    @Test
    public void shouldAcceptDoubleEncodedAmpersand() {
        assertValid("q=%2526");
    }

    /* -------------------------
     * MALFORMED ENCODING
     * ------------------------- */

    @Test
    public void shouldRejectMalformedPercentOnly() {
        assertInvalid("q=%");
    }

    @Test
    public void shouldRejectMalformedNonHexEncoding() {
        assertInvalid("q=%G1");
    }

    @Test
    public void shouldRejectUnicodeStyleEncoding() {
        assertInvalid("q=%u003C");
    }

    /* -------------------------
     * MULTI PARAMETER CASES
     * ------------------------- */

    @Test
    public void shouldRejectBadCharInSecondParamValue() {
        assertInvalid("a=ok&b=%3Cbad");
    }

    @Test
    public void shouldRejectBadCharInFirstParamKey() {
        assertInvalid("%3Ca=1&b=2");
    }

    @Test
    public void shouldRejectMixedValidAndInvalidParams() {
        assertInvalid("good=ok&bad=%00");
    }

}
