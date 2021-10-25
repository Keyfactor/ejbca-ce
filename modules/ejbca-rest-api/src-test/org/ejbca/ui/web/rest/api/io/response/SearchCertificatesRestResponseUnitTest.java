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

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A unit test class for SearchCertificatesRestResponse.
 *
 */
@RunWith(EasyMockRunner.class)
public class SearchCertificatesRestResponseUnitTest {
    
    private static final String SHOULD_PROPERLY_CONVERT = "Should properly convert.";
    private static final int TEST_CERTIFIATE_PROFILE_ID = 1;
    private static final int TEST_END_ENTITY_PROFILE_ID = 1;
    private static final String TEST_CERTIFICATE_PROFILE = "test_certificate_profile";
    private static final String TEST_END_ENTITY_PROFILE = "test_end_entity_profile";
    
    @Mock
    private CertificateProfileSessionLocal certificateProfileSession;
    
    @Mock
    private EndEntityProfileSessionLocal endEntityProfileSession;   
    
    @Test
    public void shouldProperlyConvertRaCertificateSearchResponse() throws CertificateEncodingException {
        // given
        final boolean expectedMoreResults = true;
        final String expectedSerialNumber = CertTools.getSerialNumberAsString(CaInfoBuilder.testCaCertificate);
        final String expectedResponseFormat = "DER";
        final CertificateData certificateData = new CertificateData();
        certificateData.setCertificateProfileId(TEST_CERTIFIATE_PROFILE_ID);
        certificateData.setEndEntityProfileId(TEST_END_ENTITY_PROFILE_ID);
        final List<CertificateDataWrapper> certificateDataWrappersList = Collections.singletonList(new CertificateDataWrapper(CaInfoBuilder.testCaCertificate, certificateData, null));
        final RaCertificateSearchResponse raCertificateSearchResponse = new RaCertificateSearchResponse();
        raCertificateSearchResponse.setCdws(certificateDataWrappersList);
        raCertificateSearchResponse.setMightHaveMoreResults(expectedMoreResults);
        // when
        expect(certificateProfileSession.getCertificateProfileName(TEST_CERTIFIATE_PROFILE_ID)).andReturn(TEST_CERTIFICATE_PROFILE).times(1);
        replay(certificateProfileSession);

        expect(endEntityProfileSession.getEndEntityProfileName(TEST_END_ENTITY_PROFILE_ID)).andReturn(TEST_END_ENTITY_PROFILE).times(1);
        replay(endEntityProfileSession);
        
        final SearchCertificatesRestResponse actualSearchCertificatesRestResponse = SearchCertificatesRestResponse.converter().toRestResponse(raCertificateSearchResponse, certificateProfileSession, endEntityProfileSession);
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
        verify(certificateProfileSession);
        verify(endEntityProfileSession);
    }

}
