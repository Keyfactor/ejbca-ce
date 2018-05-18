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
package org.ejbca.ui.web.rest.api.converters;

import org.cesecore.certificates.ca.CAData;
import org.ejbca.ui.web.rest.api.helpers.CADataBuilder;
import org.ejbca.ui.web.rest.api.types.CaInfoType;
import org.junit.Test;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for CaInfoConverter to test its content.
 *
 * @see org.ejbca.ui.web.rest.api.converters.CaInfoConverter
 *
 * @version $Id: CaInfoConverterUnitTest.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class CaInfoConverterUnitTest {

    private CaInfoConverter caInfoConverter = new CaInfoConverter();

    @Test
    public void shouldReturnEmptyListOfCaInfoTypeOnNullInput() {
        // given
        final List<CAData> caDataList = null;
        // when
        final List<CaInfoType> actualListOfCaInfoType = caInfoConverter.toTypes(caDataList);
        // then
        assertEquals(0, actualListOfCaInfoType.size());
    }

    @Test
    public void shouldReturnEmptyListOfCaInfoTypeOnEmptyListInput() {
        // given
        final List<CAData> caDataList = Collections.emptyList();
        // when
        final List<CaInfoType> actualListOfCaInfoType = caInfoConverter.toTypes(caDataList);
        // then
        assertEquals(0, actualListOfCaInfoType.size());
    }

    @Test
    public void shouldProperlyConvertFromCADataToCaInfoType() throws Exception {
        // given
        final String expectedSubjectDn = CADataBuilder.TEST_CA_SUBJECT_DN;
        final String expectedName = CADataBuilder.TEST_CA_NAME;
        final int expectedId = 121;
        final String expectedIssuerDn = CADataBuilder.TEST_CA_ISSUER_DN;
        final Date expectedExpirationDate = new Date();
        final CAData caData = CADataBuilder.builder()
                .subjectDn(expectedSubjectDn)
                .name(expectedName)
                .id(expectedId)
                .expirationDate(expectedExpirationDate)
                .build();
        // when
        final CaInfoType actualCaInfoType = caInfoConverter.toType(caData);
        // then
        assertEquals(expectedSubjectDn, actualCaInfoType.getSubjectDn());
        assertEquals(expectedName, actualCaInfoType.getName());
        assertEquals(expectedId, actualCaInfoType.getId());
        assertEquals(expectedIssuerDn, actualCaInfoType.getIssuerDn());
        assertEquals(expectedExpirationDate, actualCaInfoType.getExpirationDate());
    }

}