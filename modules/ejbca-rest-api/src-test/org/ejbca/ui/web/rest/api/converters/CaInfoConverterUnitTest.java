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
import org.ejbca.ui.web.rest.api.types.CaInfoType;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;

// TODO Conversion tests
// TODO Javadoc
/**
 * A unit test class for CaInfoConverter.
 *
 * @see CaInfoConverter
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

}