/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.service;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponse;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;


import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertNotNull;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaProperty;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaOperation;

/**
 * A unit test class for CertificateRestService.
 *
 * @version $Id: CertificateRestServiceUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
@RunWith(EasyMockRunner.class)
public class CertificateRestServiceUnitTest {

    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApi;

    @TestSubject
    private CertificateRestService certificateService = new CertificateRestService();

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnUnauthorizedEndEntityProfileName() throws RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.END_ENTITY_PROFILE.name())
                .value("1")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        expect(raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken)).andReturn(new HashMap<Integer, String>());
        replay(raMasterApi);
        // when
        certificateService.authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnUnauthorizedCertificateProfileName() throws RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CERTIFICATE_PROFILE.name())
                .value("1")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        expect(raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken)).andReturn(new HashMap<Integer, String>());
        replay(raMasterApi);
        // when
        certificateService.authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnUnauthorizedCAName() throws RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CA.name())
                .value("1")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        expect(raMasterApi.getAuthorizedCas(authenticationToken)).andReturn(new ArrayList<CAInfo>());
        replay(raMasterApi);
        // when
        certificateService.authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
    }

    @Test(expected = RestException.class)
    public void shouldThrowRestExceptionOnAuthorizationOfUnknownCriteriaProperty() throws RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property("BLAH")
                .value("1")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        expect(raMasterApi.getAuthorizedCas(authenticationToken)).andReturn(new ArrayList<CAInfo>());
        replay(raMasterApi);
        // when
        certificateService.authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
    }

    @Test
    public void shouldAskOnceRaMasterApiForEndEntityProfiles() throws RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.END_ENTITY_PROFILE.name())
                .value("A")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.END_ENTITY_PROFILE.name())
                .value("B")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Arrays.asList(searchCertificateCriteriaRestRequest1, searchCertificateCriteriaRestRequest2))
                .build();
        final HashMap<Integer, String> authorizedEndEntityProfileIdsMap = new HashMap<Integer, String>();
        authorizedEndEntityProfileIdsMap.put(1, "A");
        authorizedEndEntityProfileIdsMap.put(2, "B");
        expect(raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken)).andReturn(authorizedEndEntityProfileIdsMap).times(1);
        replay(raMasterApi);
        // when
        certificateService.authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
        // then
        verify(raMasterApi);
    }

    @Test
    public void shouldAskOnceRaMasterApiForCertificateProfiles() throws RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CERTIFICATE_PROFILE.name())
                .value("A")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CERTIFICATE_PROFILE.name())
                .value("B")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Arrays.asList(searchCertificateCriteriaRestRequest1, searchCertificateCriteriaRestRequest2))
                .build();
        final HashMap<Integer, String> authorizedCertificateProfileIdsMap = new HashMap<Integer, String>();
        authorizedCertificateProfileIdsMap.put(1, "A");
        authorizedCertificateProfileIdsMap.put(2, "B");
        expect(raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken)).andReturn(authorizedCertificateProfileIdsMap).times(1);
        replay(raMasterApi);
        // when
        certificateService.authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
        // then
        verify(raMasterApi);
    }

    @Test
    public void shouldAskOnceRaMasterApiForCAs() throws RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CA.name())
                .value("A")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.CA.name())
                .value("B")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Arrays.asList(searchCertificateCriteriaRestRequest1, searchCertificateCriteriaRestRequest2))
                .build();
        final List<CAInfo> authorizedCAInfos = Arrays.asList(
                CaInfoBuilder.builder().id(1).name("A").build(),
                CaInfoBuilder.builder().id(2).name("B").build()
        );
        expect(raMasterApi.getAuthorizedCas(authenticationToken)).andReturn(authorizedCAInfos).times(1);
        replay(raMasterApi);
        // when
        certificateService.authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
        // then
        verify(raMasterApi);
    }

    @Test
    public void shouldUseRaMasterApiToSearchCertificates() throws CertificateEncodingException, RestException {
        // given
        final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest = SearchCertificateCriteriaRestRequest.builder()
                .property(CriteriaProperty.QUERY.name())
                .value("A")
                .operation(CriteriaOperation.EQUAL.name())
                .build();
        final SearchCertificatesRestRequest searchCertificatesRestRequest = SearchCertificatesRestRequest.builder()
                .maxNumberOfResults(11)
                .criteria(Collections.singletonList(searchCertificateCriteriaRestRequest))
                .build();
        final RaCertificateSearchResponse expectedRaCertificateSearchResponse = new RaCertificateSearchResponse();
        expect(raMasterApi.searchForCertificates(anyObject(AuthenticationToken.class), anyObject(RaCertificateSearchRequest.class))).andReturn(expectedRaCertificateSearchResponse);
        replay(raMasterApi);
        // when
        final SearchCertificatesRestResponse actualSearchCertificatesRestResponse = certificateService.searchCertificates(authenticationToken, searchCertificatesRestRequest);
        // then
        verify(raMasterApi);
        assertNotNull("Should return non null response.", actualSearchCertificatesRestResponse);
    }

}

