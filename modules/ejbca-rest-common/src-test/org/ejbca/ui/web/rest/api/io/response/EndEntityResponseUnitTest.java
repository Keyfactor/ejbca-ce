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
package org.ejbca.ui.web.rest.api.io.response;

import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.ui.web.rest.api.util.AssertUtil;
import org.junit.Test;
import java.util.List;

public class EndEntityResponseUnitTest {

    private static ExtendedInformationRestResponseComponent getComponent(String name) {
        return new ExtendedInformationRestResponseComponent
                .ExtendedInformationRestResponseComponentBuilder()
                .setName(name)
                .build();
    }

    @Test
    public void testConstructor_null() {
        // Given
        EndEntityRestResponse response = EndEntityRestResponse
                .builder()
                .setExtensionData(null)
                .build();

        // When
        final var actual = response.getExtensionData();

        // Then
        AssertUtil.assertEquals(null, actual);
    }

    @Test
    public void testConstructor_empty() {
        // Given
        EndEntityRestResponse response = EndEntityRestResponse
                .builder()
                .setExtensionData(List.of())
                .build();

        // When
        final var actual = response.getExtensionData();

        // Then
        AssertUtil.assertEquals(List.of(), actual);
    }

    @Test
    public void testConstructor_noInternal() {
        // Given
        var expected = List.of(
                getComponent("abc"),
                getComponent("def"),
                getComponent("ghi"));
        EndEntityRestResponse response = EndEntityRestResponse
                .builder()
                .setExtensionData(expected)
                .build();

        // When
        final var actual = response.getExtensionData();

        // Then
        AssertUtil.assertEquals(expected, actual);
    }

    @Test
    public void testConstructor_withInternal() {
        // Given
        var responseComponents = List.of(
                getComponent("abc"),
                getComponent("xyz"+ ExtendedInformation.INTERNAL_KEY_PREFIX),
                getComponent("def"),
                getComponent(ExtendedInformation.INTERNAL_KEY_PREFIX+"tuv"),
                getComponent(ExtendedInformation.INTERNAL_KEY_PREFIX),
                getComponent("ghi"));
        var expected = List.of(
                getComponent("abc"),
                getComponent("def"),
                getComponent("ghi"));
        EndEntityRestResponse response = EndEntityRestResponse
                .builder()
                .setExtensionData(responseComponents)
                .build();

        // When
        final var actual = response.getExtensionData();

        // Then
        AssertUtil.assertEquals(expected, actual);
    }

}
