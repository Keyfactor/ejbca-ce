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
package org.ejbca.ui.web.admin.ca.validators;

import javax.faces.validator.ValidatorException;

import org.junit.Test;

/**
 * Unit test of CrlDistributionPointUrlValidator
 */
public class CrlDistributionPointUrlValidatorUnitTest extends JsfValidatorTestBase {

    public void validateUrl(final String url) {
        new CrlDistributionPointUrlValidator().validate(getMockedFacesContext(), getMockedUiComponent(), url);
    }

    // Tests of good URLs
    @Test
    public void emptyCdp() {
        validateUrl("");
    }

    @Test
    public void basicUrl() {
        validateUrl("https://crl.example.com/crl");
    }

    @Test
    public void quotedUrl() {
        validateUrl("\"https://crl.example.com/crl;abc\"");
    }

    @Test
    public void multipleUrls() {
        validateUrl("\"https://crl.example.com/crl;abc\"");
    }

    @Test
    public void multipleQuotedUrl() {
        validateUrl("\"https://crl.example.com/crl;abc\";\"https://other.example/;crl\"");
    }

    // Tests of bad URLs
    @Test(expected = ValidatorException.class)
    public void badUrl() {
        validateUrl("x");
    }

    @Test(expected = ValidatorException.class)
    public void badSecondUrl() {
        validateUrl("\"https://crl.example.com/\";bad");
    }

}
