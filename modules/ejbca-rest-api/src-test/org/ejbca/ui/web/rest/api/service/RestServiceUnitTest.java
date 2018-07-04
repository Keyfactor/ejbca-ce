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
 * @version $Id: RestServiceUnitTest.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
@RunWith(EasyMockRunner.class)
public class RestServiceUnitTest {

    private static final AuthenticationToken authenticationToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("TestRunner"));

    @Mock
    private RaMasterApiProxyBeanLocal raMasterApi;

    @TestSubject
    private RestService service = new RestService();

    @Test
    public void shouldUseRaMasterApiToGetListOfAuthorizedEndEntityProfileIds() {
        // given
        final Integer expectedId = 121;
        final Map<Integer, String> expectedMap = new HashMap<>();
        expectedMap.put(expectedId, "A");
        expect(raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken)).andReturn(expectedMap);
        replay(raMasterApi);
        // when
        final List<Integer> actualResult = service.getAuthorizedEndEntityProfileIds(authenticationToken);
        // then
        verify(raMasterApi);
        assertEquals(1, actualResult.size());
        assertEquals(expectedId, actualResult.get(0));
    }

    @Test
    public void shouldUseRaMasterApiToGetListOfAuthorizedCertificateProfileIds() {
        // given
        final Integer expectedId = 121;
        final Map<Integer, String> expectedMap = new HashMap<>();
        expectedMap.put(expectedId, "A");
        expect(raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken)).andReturn(expectedMap);
        replay(raMasterApi);
        // when
        final List<Integer> actualResult = service.getAuthorizedCertificateProfileIds(authenticationToken);
        // then
        verify(raMasterApi);
        assertEquals(1, actualResult.size());
        assertEquals(expectedId, actualResult.get(0));
    }

    @Test
    public void shouldUseRaMasterApiToGetListOfAuthorizedCas() {
        // given
        final Integer expectedId = 121;
        final CAInfo cAInfo = CaInfoBuilder.builder()
                .id(expectedId)
                .build();
        final List<CAInfo> expectedList = Collections.singletonList(cAInfo);
        expect(raMasterApi.getAuthorizedCas(authenticationToken)).andReturn(expectedList);
        replay(raMasterApi);
        // when
        final List<Integer> actualResult = service.getAuthorizedCAIds(authenticationToken);
        // then
        verify(raMasterApi);
        assertEquals(1, actualResult.size());
        assertEquals(expectedId, actualResult.get(0));
    }

}
