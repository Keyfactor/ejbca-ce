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

import jakarta.ws.rs.core.Response;
import org.apache.log4j.Logger;
import org.cesecore.junit.util.TraceLogMethodsTestWatcher;
import org.ejbca.config.GlobalConfiguration;
import org.json.simple.parser.JSONParser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;

public class ApprovalRestResourceSystemTest extends RestResourceSystemTestBase {

    private static final Logger log = Logger.getLogger(CaManagementRestResourceSystemTest.class);
    private static final JSONParser jsonParser = new JSONParser();

    @Rule
    public final TestWatcher traceLogMethodsRule = new TraceLogMethodsTestWatcher(log);

    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }

    @Test
    public void shouldReturnStatusInformation() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // when
        final Response actualResponse = newRequest("/v1/approval/status").request().get();
        final String actualJsonString = actualResponse.readEntity(String.class);
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }

}
