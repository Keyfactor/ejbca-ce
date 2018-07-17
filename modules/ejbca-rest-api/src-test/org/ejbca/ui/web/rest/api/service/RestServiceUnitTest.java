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
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.helpers.CaInfoBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

/**
 * A unit test class for CertificateRestService.
 *
 * @version $Id: RestServiceUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
@RunWith(EasyMockRunner.class)
public class RestServiceUnitTest {

    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApi;

    @TestSubject
    private RestService service = new RestService();

    @Test
    public void shouldUseRaMasterApiToGetMapOfAuthorizedEndEntityProfiles() {
        // given
        final Integer expectedId = 121;
        final String expectedName = "A";
        final Map<Integer, String> expectedMap = new HashMap<>();
        expectedMap.put(expectedId, expectedName);
        expect(raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken)).andReturn(expectedMap);
        replay(raMasterApi);
        // when
        final Map<Integer, String> actualResult = service.getAuthorizedEndEntityProfiles(authenticationToken);
        // then
        verify(raMasterApi);
        assertEquals("Should return map.", 1, actualResult.size());
        assertEquals("Should return unmodified response.", expectedName, actualResult.get(expectedId));
    }

    @Test
    public void shouldUseRaMasterApiToGetMapOfAuthorizedCertificateProfiles() {
        // given
        final Integer expectedId = 121;
        final String expectedName = "A";
        final Map<Integer, String> expectedMap = new HashMap<>();
        expectedMap.put(expectedId, expectedName);
        expect(raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken)).andReturn(expectedMap);
        replay(raMasterApi);
        // when
        final Map<Integer, String> actualResult = service.getAuthorizedCertificateProfiles(authenticationToken);
        // then
        verify(raMasterApi);
        assertEquals("Should return map.", 1, actualResult.size());
        assertEquals("Should return unmodified response.", expectedName, actualResult.get(expectedId));
    }

    @Test
    public void shouldUseRaMasterApiToGetMapOfAuthorizedCas() {
        // given
        final Integer expectedId = 121;
        final String expectedName = "A";
        final CAInfo cAInfo = CaInfoBuilder.builder()
                .id(expectedId)
                .name(expectedName)
                .build();
        final List<CAInfo> expectedList = Collections.singletonList(cAInfo);
        expect(raMasterApi.getAuthorizedCas(authenticationToken)).andReturn(expectedList);
        replay(raMasterApi);
        // when
        final Map<Integer, String> actualResult = service.getAuthorizedCAs(authenticationToken);
        // then
        verify(raMasterApi);
        assertEquals("Should return map.", 1, actualResult.size());
        assertEquals("Should return unmodified response.", expectedName, actualResult.get(expectedId));
    }

}
