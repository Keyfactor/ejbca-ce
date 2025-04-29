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
package org.ejbca.ui.web.admin.configuration;

import jakarta.faces.application.Application;
import jakarta.faces.application.FacesMessage;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.easymock.Capture;
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
import static org.junit.Assert.*;

@RunWith(EasyMockRunner.class)
public class CustomCertExtensionMBeanUnitTest {

	private CustomCertExtensionMBean customCertExtensionMBean;
	private AvailableCustomCertificateExtensionsConfiguration cceConfig;

	private SystemConfigMBean systemConfigMBean;
	private FacesContext facesContext;
	private EjbcaWebBean ejbcaWebBean;
	private EjbBridgeSessionLocal ejbBridgeSession;
	private ExternalContext externalContext;
	private Application application;
	private EjbcaJSFHelper ejbcaJSFHelper;

	@Before
	public void setUp() throws Exception {
		cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
		systemConfigMBean = createMock(SystemConfigMBean.class);

		// Mocks
		facesContext = EasyMock.createStrictMock(FacesContext.class);
		externalContext = createMock(ExternalContext.class);
		application = createMock(Application.class);
		ejbcaJSFHelper = createMock(EjbcaJSFHelper.class);
		ejbcaWebBean = createMock(EjbcaWebBean.class);
		ejbBridgeSession = new MockedEjbBridgeSession();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		expect(application.evaluateExpressionGet(facesContext, "#{web}", EjbcaJSFHelper.class)).andReturn(
				ejbcaJSFHelper).anyTimes();
		expect(ejbcaJSFHelper.getEjbcaWebBean()).andReturn(ejbcaWebBean).anyTimes();

		replay(externalContext, application, ejbcaJSFHelper);

		setCurrentFacesContext(facesContext);
	}

	@Test
	public void testSaveCurrentExtension() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();
		ejbcaWebBean.saveAvailableCustomCertExtensionsConfiguration(anyObject(AvailableCustomCertificateExtensionsConfiguration.class));
		EasyMock.expectLastCall().once();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(1).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);
		customCertExtensionMBean.getCurrentExtensionGUIInfo(); // populate
		customCertExtensionMBean.getCurrentExtensionPropertiesList(); // populate

		// When
		customCertExtensionMBean.saveCurrentExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_INFO, messageCapture.getValue().getSeverity());
		assertEquals("Extension was saved successfully.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testSaveCurrentExtensionWithoutOid() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		cceConfig.addCustomCertExtension(1, "", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(1).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);
		customCertExtensionMBean.getCurrentExtensionGUIInfo(); // populate
		customCertExtensionMBean.getCurrentExtensionPropertiesList(); // populate

		// When
		customCertExtensionMBean.saveCurrentExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("No CustomCertificateExtension OID is set.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testSaveCurrentExtensionWithoutLabel() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		cceConfig.addCustomCertExtension(1, "1.2.3.4", "", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(1).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);
		customCertExtensionMBean.getCurrentExtensionGUIInfo(); // populate
		customCertExtensionMBean.getCurrentExtensionPropertiesList(); // populate

		// When
		customCertExtensionMBean.saveCurrentExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("No CustomCertificateExtension Label is set.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testSaveCurrentExtensionNonUniqueOid() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "1.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(2).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);
		customCertExtensionMBean.getCurrentExtensionGUIInfo(); // populate
		customCertExtensionMBean.getCurrentExtensionPropertiesList(); // populate

		// When
		customCertExtensionMBean.saveCurrentExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("CustomCertificateExtension OID '1.2.3.4' already exist in database.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testSaveCurrentExtensionNonUniqueLabel() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(2).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);
		customCertExtensionMBean.getCurrentExtensionGUIInfo(); // populate
		customCertExtensionMBean.getCurrentExtensionPropertiesList(); // populate

		// When
		customCertExtensionMBean.saveCurrentExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("CustomCertificateExtension Label 'TESTEXTENSION1' already exist in database.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testSaveCurrentExtensionError() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();
		ejbcaWebBean.saveAvailableCustomCertExtensionsConfiguration(anyObject(AvailableCustomCertificateExtensionsConfiguration.class));
		EasyMock.expectLastCall().andThrow(new RuntimeException(""));

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(1).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);
		customCertExtensionMBean.getCurrentExtensionGUIInfo(); // populate
		customCertExtensionMBean.getCurrentExtensionPropertiesList(); // populate

		// When
		customCertExtensionMBean.saveCurrentExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("Failed to edit Custom Certificate Extension. ", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	// --------------------------------------------
	//
	// --------------------------------------------

	@Test
	public void testIsOidUnique() throws CertificateExtentionConfigurationException {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(3, "3.2.3.4", "TESTEXTENSION3", BasicCertificateExtension.class.getName(), false, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(3).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);

		// When
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

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(3).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);

		// When
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

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(4).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);

		// When
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

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		expect(systemConfigMBean.getSelectedCustomCertExtensionID()).andReturn(4).anyTimes();

		replay(ejbcaWebBean, facesContext, systemConfigMBean);

		customCertExtensionMBean = new CustomCertExtensionMBean();
		customCertExtensionMBean.setSystemConfigMBean(systemConfigMBean);

		// When
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
