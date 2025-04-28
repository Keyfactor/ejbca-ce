/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.configuration;

import jakarta.faces.application.Application;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
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
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(EasyMockRunner.class)
public class CustomCertExtensionMBeanUnitTest {

	private CustomCertExtensionMBean customCertExtensionMBean;
	private AvailableCustomCertificateExtensionsConfiguration cceConfig;

	private SystemConfigMBean systemConfigMBean;

	@Before
	public void setUp() throws Exception {
		cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
		systemConfigMBean = createMock(SystemConfigMBean.class);

		// Mocks
		final FacesContext facesContext = EasyMock.createStrictMock(FacesContext.class);
		final ExternalContext externalContext = createMock(ExternalContext.class);
		final Application application = createMock(Application.class);
		final EjbcaJSFHelper ejbcaJSFHelper = createMock(EjbcaJSFHelper.class);
		final EjbcaWebBean ejbcaWebBean = createMock(EjbcaWebBean.class);
		final EjbBridgeSessionLocal ejbBridgeSession = new MockedEjbBridgeSession();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		expect(application.evaluateExpressionGet(facesContext, "#{web}", EjbcaJSFHelper.class)).andReturn(ejbcaJSFHelper).anyTimes();
		expect(ejbcaJSFHelper.getEjbcaWebBean()).andReturn(ejbcaWebBean).anyTimes();
		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		replay(facesContext, externalContext, application, ejbcaJSFHelper, ejbcaWebBean);

		setCurrentFacesContext(facesContext);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);
	}

	@Test
	public void testIsOidUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(3, "3.2.3.4", "TESTEXTENSION3", BasicCertificateExtension.class.getName(), false, true, null);

		// When
		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(3).anyTimes();
		replay(systemConfigMBean);

		final boolean result = customCertExtensionMBean.isOidUnique(cceConfig);

		// Expect
		assertTrue("OID Should be unique", result);
	}

	@Test
	public void testIsOidNotUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(3, "2.2.3.4", "TESTEXTENSION3", BasicCertificateExtension.class.getName(), false, true, null);

		// When
		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(3).anyTimes();
		replay(systemConfigMBean);

		final boolean result = customCertExtensionMBean.isOidUnique(cceConfig);

		// Expect
		assertFalse("OID Should NOT be unique", result);
	}

	@Test
	public void testIsDisplayNameUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(4, "4.2.3.4", "TESTEXTENSION4", BasicCertificateExtension.class.getName(), false, true, null);

		// When
		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(4).anyTimes();
		replay(systemConfigMBean);

		final boolean result = customCertExtensionMBean.isDisplayNameUnique(cceConfig);

		// Expect
		assertTrue("Display Name Should be unique", result);
	}

	@Test
	public void testIsDisplayNameNotUnique() throws CertificateExtentionConfigurationException {
		// Given
		Properties props = new Properties();
		props.put("translatable", "FALSE");
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("value", "Test 111");
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);

		props = new Properties();
		props.put("translatable", "FALSE");
		props.put("encoding", "DERPRINTABLESTRING");
		props.put("value", "Test 222");
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		props = new Properties();
		props.put("translatable", "TRUE");
		props.put("value", "Test 444");
		cceConfig.addCustomCertExtension(4, "4.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), false, true, null);

		// When
		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(4).anyTimes();
		replay(systemConfigMBean);

		final boolean result = customCertExtensionMBean.isDisplayNameUnique(cceConfig);

		// Expect
		assertFalse("Display Name Should NOT be unique", result);
	}

	private void setCurrentFacesContext(FacesContext ctx) throws Exception {
		final Method setter = FacesContext.class.getDeclaredMethod("setCurrentInstance", FacesContext.class);
		setter.setAccessible(true);
		setter.invoke(null, ctx);
	}

}
