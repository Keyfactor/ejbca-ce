package org.ejbca.ui.web.admin.configuration;

import jakarta.faces.application.Application;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Method;
import java.util.Properties;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(EasyMockRunner.class)
public class SystemConfigMBeanUnitTest {

	private SystemConfigMBean systemConfigMBean;
	private AvailableCustomCertificateExtensionsConfiguration cceConfig;

	@Before
	public void setUp() throws Exception {
		cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

		// Mocks
		final FacesContext facesContext = EasyMock.createStrictMock(FacesContext.class);
		final ExternalContext externalContext = createMock(ExternalContext.class);
		final Application application = createMock(Application.class);
		final EjbcaJSFHelper ejbcaJSFHelper = createMock(EjbcaJSFHelper.class);
		final EjbcaWebBean ejbcaWebBean = createMock(EjbcaWebBean.class);
		final EjbBridgeSessionLocal ejbBridgeSession = new MockedEjbBridgeSession();
		final AuthenticationToken authenticationToken = createMock(AuthenticationToken.class);
		final AuthorizationSessionLocal authorizationSession = ejbBridgeSession.getAuthorizationSession();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		expect(application.evaluateExpressionGet(facesContext, "#{web}", EjbcaJSFHelper.class)).andReturn(ejbcaJSFHelper).anyTimes();
		expect(ejbcaJSFHelper.getEjbcaWebBean()).andReturn(ejbcaWebBean).anyTimes();
		expect(ejbcaJSFHelper.getAdmin()).andReturn(authenticationToken).anyTimes();
		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(authorizationSession.isAuthorized(anyObject(), anyObject())).andReturn(true).anyTimes();

		replay(facesContext, externalContext, application, ejbcaJSFHelper, ejbcaWebBean, authenticationToken, authorizationSession);

		setCurrentFacesContext(facesContext);

		systemConfigMBean = new SystemConfigMBean();
	}

	@Test
	public void testIsOidUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		systemConfigMBean.setNewOID("3.2.3.4");

		// When
		final boolean result = systemConfigMBean.isOidUnique(cceConfig);

		// Expect
		assertTrue("OID Should be unique", result);
	}

	@Test
	public void testIsOidNotUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		systemConfigMBean.setNewOID("2.2.3.4");

		// When
		final boolean result = systemConfigMBean.isOidUnique(cceConfig);

		// Expect
		assertFalse("OID Should NOT be unique", result);
	}

	@Test
	public void testIsDisplayNameUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		systemConfigMBean.setNewDisplayName("TESTEXTENSION4");

		// When
		final boolean result = systemConfigMBean.isDisplayNameUnique(cceConfig);

		// Expect
		assertTrue("Display Name Should be unique", result);
	}

	@Test
	public void testIsDisplayNameNotUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		systemConfigMBean.setNewDisplayName("TESTEXTENSION1");

		// When
		final boolean result = systemConfigMBean.isDisplayNameUnique(cceConfig);

		// Expect
		assertFalse("Display Name Should NOT be unique", result);
	}

	private void setCurrentFacesContext(FacesContext ctx) throws Exception {
		final Method setter = FacesContext.class.getDeclaredMethod("setCurrentInstance", FacesContext.class);
		setter.setAccessible(true);
		setter.invoke(null, ctx);
	}

}
