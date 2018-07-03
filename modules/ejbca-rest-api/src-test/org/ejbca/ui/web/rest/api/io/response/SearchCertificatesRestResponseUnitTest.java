/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.junit.Test;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * A unit test class for SearchCertificatesRestResponse.
 *
 * @version $Id: SearchCertificatesRestResponseUnitTest.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class SearchCertificatesRestResponseUnitTest {

    @Test
    public void shouldProperlyConvertRaCertificateSearchResponse() throws CertificateEncodingException {
        // given
        final boolean expectedMoreResults = true;
        final BigInteger expectedSerialNumber = CertTools.getSerialNumber(CaInfoBuilder.testCaCertificate);
        final String expectedResponseFormat = "DER";
        final List<CertificateDataWrapper> certificateDataWrappersList = Collections.singletonList(new CertificateDataWrapper(CaInfoBuilder.testCaCertificate, null, null));
        final RaCertificateSearchResponse raCertificateSearchResponse = new RaCertificateSearchResponse();
        raCertificateSearchResponse.setCdws(certificateDataWrappersList);
        raCertificateSearchResponse.setMightHaveMoreResults(expectedMoreResults);
        // when
        final SearchCertificatesRestResponse actualSearchCertificatesRestResponse = SearchCertificatesRestResponse.converter().toRestResponse(raCertificateSearchResponse);
        // then
        assertEquals(expectedMoreResults, actualSearchCertificatesRestResponse.isMoreResults());
        assertNotNull(actualSearchCertificatesRestResponse.getCertificates());
        assertEquals(1, actualSearchCertificatesRestResponse.getCertificates().size());
        final CertificateRestResponse actualCertificateRestResponse = actualSearchCertificatesRestResponse.getCertificates().get(0);
        assertEquals(expectedSerialNumber, actualCertificateRestResponse.getSerialNumber());
        assertArrayEquals(Base64.encode(CaInfoBuilder.testCaCertificate.getEncoded()), actualCertificateRestResponse.getCertificate());
        assertEquals(expectedResponseFormat, actualCertificateRestResponse.getResponseFormat());
    }

}
