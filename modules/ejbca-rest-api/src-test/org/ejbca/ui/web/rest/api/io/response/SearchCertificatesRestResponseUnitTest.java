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

import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * A unit test class for SearchCertificatesRestResponse.
 *
 */
public class SearchCertificatesRestResponseUnitTest {
    
    private static final String SHOULD_PROPERLY_CONVERT = "Should properly convert.";
    private static final int TEST_CERTIFICATE_PROFILE_ID = 1;
    private static final int TEST_END_ENTITY_PROFILE_ID = 1;
    private static final String TEST_CERTIFICATE_PROFILE = "test_certificate_profile";
    private static final String TEST_END_ENTITY_PROFILE = "test_end_entity_profile";
    
    @Test
    public void shouldProperlyConvertRaCertificateSearchResponse() throws CertificateEncodingException {
        // given
        final boolean expectedMoreResults = true;
        final String expectedSerialNumber = CertTools.getSerialNumberAsString(CaInfoBuilder.testCaCertificate);
        final String expectedResponseFormat = "DER";
        final CertificateData certificateData = new CertificateData();
        certificateData.setCertificateProfileId(TEST_CERTIFICATE_PROFILE_ID);
        certificateData.setEndEntityProfileId(TEST_END_ENTITY_PROFILE_ID);
        final List<CertificateDataWrapper> certificateDataWrappersList = Collections.singletonList(new CertificateDataWrapper(CaInfoBuilder.testCaCertificate, certificateData, null));
        final RaCertificateSearchResponse raCertificateSearchResponse = new RaCertificateSearchResponse();
        raCertificateSearchResponse.setCdws(certificateDataWrappersList);
        raCertificateSearchResponse.setMightHaveMoreResults(expectedMoreResults);
        Map<Integer, String> availableEndEntityProfiles = new HashMap<>();
        Map<Integer, String> availableCertificateProfiles = new HashMap<>();
        availableEndEntityProfiles.put(TEST_END_ENTITY_PROFILE_ID, TEST_END_ENTITY_PROFILE);
        availableCertificateProfiles.put(TEST_CERTIFICATE_PROFILE_ID, TEST_CERTIFICATE_PROFILE);
        
        final SearchCertificatesRestResponse actualSearchCertificatesRestResponse = 
                SearchCertificatesRestResponse.converter().toRestResponse(raCertificateSearchResponse, availableEndEntityProfiles, availableCertificateProfiles);
        // then
        assertEquals(SHOULD_PROPERLY_CONVERT, expectedMoreResults, actualSearchCertificatesRestResponse.isMoreResults());
        assertNotNull(SHOULD_PROPERLY_CONVERT, actualSearchCertificatesRestResponse.getCertificates());
        assertEquals(SHOULD_PROPERLY_CONVERT, 1, actualSearchCertificatesRestResponse.getCertificates().size());
        final CertificateRestResponse actualCertificateRestResponse = actualSearchCertificatesRestResponse.getCertificates().get(0);
        assertEquals(SHOULD_PROPERLY_CONVERT, expectedSerialNumber, actualCertificateRestResponse.getSerialNumber());
        assertArrayEquals(SHOULD_PROPERLY_CONVERT, Base64.encode(CaInfoBuilder.testCaCertificate.getEncoded()), actualCertificateRestResponse.getCertificate());
        assertEquals(SHOULD_PROPERLY_CONVERT, expectedResponseFormat, actualCertificateRestResponse.getResponseFormat());
        assertEquals(SHOULD_PROPERLY_CONVERT, TEST_CERTIFICATE_PROFILE, actualCertificateRestResponse.getCertificateProfile());
        assertEquals(SHOULD_PROPERLY_CONVERT, TEST_END_ENTITY_PROFILE, actualCertificateRestResponse.getEndEntityProfile());

    }

}
