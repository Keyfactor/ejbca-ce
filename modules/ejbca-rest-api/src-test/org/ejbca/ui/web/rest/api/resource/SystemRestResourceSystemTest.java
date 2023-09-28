package org.ejbca.ui.web.rest.api.resource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Properties;
import javax.ws.rs.core.Response;

import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * A test class for SystemRestResourceTest to test running a specified existing service.
 */
public class SystemRestResourceSystemTest extends RestResourceSystemTestBase {
        
    private static final String SERVICE_NAME = "TestService";
    private ServiceSessionRemote serviceSession; 
    private ServiceConfiguration serviceConfig = new ServiceConfiguration();
    private final String caName = "SystemResourceTestCA";
    private final String cryptoTokenName = "SystemResourceTestCryptoToken";
    private final String caDN = "CN=SystemResourceTestCA";


    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();

    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException {
        // remove CA
        CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName);
        // remove cryptotoken
        CryptoTokenTestUtils.removeCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName);
    }
 
    @Test
    public void shouldReturn200WhenServiceTriggered() throws Exception {
        if (serviceSession == null) {
          serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        }
        //given
        addAndActivateService(SERVICE_NAME, createServiceConfiguration(), caName);
        //verify the service ws created
        assertNotNull("Service of name " + SERVICE_NAME + " was not created", serviceSession.getService(SERVICE_NAME));
        //when
        final Response actualResponse = newRequest("/v1/system/service/" + SERVICE_NAME + "/run").request().put(null);
        try {
            final int status = actualResponse.getStatus();
            // Verify result of rest request
            //then
            assertEquals(HTTP_STATUS_CODE_OK, status);
        } finally {
            actualResponse.close();
        }
    }

    @Test
    public void shouldReturn404WhenServiceNotFound() throws Exception {
        if (serviceSession == null) {
            serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
          }
        //given
        serviceSession.removeService(INTERNAL_ADMIN_TOKEN, SERVICE_NAME);
        assertNull("Service of name " + SERVICE_NAME + " should have been removed before the request", serviceSession.getService(SERVICE_NAME));
        //when
        final Response actualResponse = newRequest("/v1/system/service/" + SERVICE_NAME + "/run").request().put(null);
        try {
            final int status = actualResponse.getStatus();
            // Verify result
            //then
            assertEquals(HTTP_STATUS_CODE_NOT_FOUND, status);
        } finally {
            actualResponse.close();
        }
    }
    
    private int addAndActivateService(final String name, final ServiceConfiguration config, final String caName) throws Exception {
        CaTestUtils.createX509Ca(INTERNAL_ADMIN_TOKEN, cryptoTokenName, caName, caDN, CAConstants.CA_OFFLINE);
        if ((config.getIntervalProperties() != null) && (config.getIntervalProperties().getProperty(PeriodicalInterval.PROP_VALUE) == null)) {
            Properties intervalprop = new Properties();
            intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "30");
            intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
            config.setIntervalProperties(intervalprop);            
        }
        config.setWorkerClassPath(UserPasswordExpireWorker.class.getName());
        Properties workerprop = new Properties();
        workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(CaTestUtils.getCaIdByName(INTERNAL_ADMIN_TOKEN, caName)));
        workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, "5");
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        config.setWorkerProperties(workerprop);
        serviceSession.addService(INTERNAL_ADMIN_TOKEN, name, config);
        serviceSession.activateServiceTimer(INTERNAL_ADMIN_TOKEN, name);        
        return serviceSession.getServiceId(name);
    }
    
    private ServiceConfiguration createServiceConfiguration() {
        serviceConfig.setActive(false);
        serviceConfig.setDescription("Description");
        serviceConfig.setActionClassPath(NoAction.class.getName());
        serviceConfig.setActionProperties(null);
        serviceConfig.setIntervalClassPath(PeriodicalInterval.class.getName());
        return serviceConfig;
    }
}
