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

import org.junit.Test;

import jakarta.faces.validator.ValidatorException;

/**
 * Unit test of PartitionedCrlUrlValidator
 */
public class PartitionedCrlUrlValidatorUnitTest extends JsfValidatorTestBase  {

    public void validateUrl(final String url) {
        final PartitionedCrlUrlValidator fieldValidator = new PartitionedCrlUrlValidator() {
            @Override
            protected String lookupErrorMessage(jakarta.faces.component.UIComponent uiComponent) {
                return "Mock error message";
            }
        };
        fieldValidator.validate(getMockedFacesContext(), getMockedUiComponent(), url);
    }

    // Tests of good URLs
    @Test
    public void onePartitionedCdpUrl() {
        validateUrl("http://crl.example/crl*.crl");
    }

    @Test
    public void multiplePartitionedCdpUrls() {
        validateUrl("http://crl.example/crl*.crl;\"https://other.example/crl?n=*\"");
    }

    // Tests of bad URLs
    @Test(expected = ValidatorException.class)
    public void missingPartitionAsterisk() {
        validateUrl("https://crl.example/crl.crl");
    }

    @Test(expected = ValidatorException.class)
    public void missingPartitionAsteriskMultipleUrls() {
        validateUrl("https://crl.example/crl*.crl;\"http://other.example/crl?n=\"");
    }
}
