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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.junit.Test;

/**
 * A unit test class for SearchCertificatesRestResponse.
 *
 * @version $Id: SearchCertificatesRestResponseUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class SearchCertificatesRestResponseUnitTest {

    @Test
    public void shouldProperlyConvertRaCertificateSearchResponse() throws CertificateEncodingException {
        // given
        final boolean expectedMoreResults = true;
        final String expectedSerialNumber = CertTools.getSerialNumberAsString(CaInfoBuilder.testCaCertificate);
        final String expectedResponseFormat = "DER";
        final List<CertificateDataWrapper> certificateDataWrappersList = Collections.singletonList(new CertificateDataWrapper(CaInfoBuilder.testCaCertificate, null, null));
        final RaCertificateSearchResponse raCertificateSearchResponse = new RaCertificateSearchResponse();
        raCertificateSearchResponse.setCdws(certificateDataWrappersList);
        raCertificateSearchResponse.setMightHaveMoreResults(expectedMoreResults);
        // when
        final SearchCertificatesRestResponse actualSearchCertificatesRestResponse = SearchCertificatesRestResponse.converter().toRestResponse(raCertificateSearchResponse);
        // then
        assertEquals("Should properly convert.", expectedMoreResults, actualSearchCertificatesRestResponse.isMoreResults());
        assertNotNull("Should properly convert.", actualSearchCertificatesRestResponse.getCertificates());
        assertEquals("Should properly convert.", 1, actualSearchCertificatesRestResponse.getCertificates().size());
        final CertificateRestResponse actualCertificateRestResponse = actualSearchCertificatesRestResponse.getCertificates().get(0);
        assertEquals("Should properly convert.", expectedSerialNumber, actualCertificateRestResponse.getSerialNumber());
        assertArrayEquals("Should properly convert.", Base64.encode(CaInfoBuilder.testCaCertificate.getEncoded()), actualCertificateRestResponse.getCertificate());
        assertEquals("Should properly convert.", expectedResponseFormat, actualCertificateRestResponse.getResponseFormat());
    }

}
