/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;

import javax.ws.rs.core.Response.Status;

import org.ejbca.config.GlobalConfiguration;
import org.jboss.resteasy.client.ClientResponse;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * A set of system tests for CaRestResource ('').
 *
 * @version $Id: CaRestResourceSystemTest.java 29137 2018-06-07 12:40:12Z andrey_s_helmes $
 */
public class CaRestResourceSystemTest extends RestResourceSystemTestBase {

    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void shouldReturnStatusInformation() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // when
        final ClientResponse<?> actualResponse = newRequest("/v1/ca/status").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        // then
        assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }

    /**
     * Disables REST and then runs a simple REST access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws Exception 
     */
    @Test
    public void shouldRestrictAccessToRestResourceIfProtocolDisabled() throws Exception {
        // given
        disableRestProtocolConfiguration();
        // when
        final ClientResponse<?> actualResponse = newRequest("/v1/ca/status").get();
        final int status = actualResponse.getStatus();
        // then
        assertEquals("Unexpected response after disabling protocol", 403, status);
        // restore state
        enableRestProtocolConfiguration();
    }
}
