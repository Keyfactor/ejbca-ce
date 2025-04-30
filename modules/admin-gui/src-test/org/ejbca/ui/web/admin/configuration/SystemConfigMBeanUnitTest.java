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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Method;
import java.util.Collections;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

@RunWith(EasyMockRunner.class)
public class SystemConfigMBeanUnitTest {

	private SystemConfigMBean systemConfigMBean;
	private AvailableCustomCertificateExtensionsConfiguration cceConfig;
	private EjbcaWebBean ejbcaWebBean;
	private EjbBridgeSessionLocal ejbBridgeSession;
	private FacesContext facesContext;
	private ExternalContext externalContext;
	private Application application;
	private EjbcaJSFHelper ejbcaJSFHelper;

	@Before
	public void setUp() throws Exception {
		cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

		// Mocks
		facesContext = EasyMock.createStrictMock(FacesContext.class);
		externalContext = createMock(ExternalContext.class);
		application = createMock(Application.class);
		ejbcaJSFHelper = createMock(EjbcaJSFHelper.class);
		ejbcaWebBean = createMock(EjbcaWebBean.class);
		ejbBridgeSession = new MockedEjbBridgeSession();

		final AuthenticationToken authenticationToken = createMock(AuthenticationToken.class);
		final AuthorizationSessionLocal authorizationSession = ejbBridgeSession.getAuthorizationSession();
		final CertificateProfileSessionLocal certificateProfileSession = ejbBridgeSession.getCertificateProfileSession();
		final GlobalConfigurationSessionLocal globalConfigurationSession = ejbBridgeSession.getGlobalConfigurationSession();

		expect(application.evaluateExpressionGet(facesContext, "#{web}", EjbcaJSFHelper.class)).andReturn(
				ejbcaJSFHelper).anyTimes();
		expect(ejbcaJSFHelper.getEjbcaWebBean()).andReturn(ejbcaWebBean).anyTimes();
		expect(ejbcaJSFHelper.getAdmin()).andReturn(authenticationToken).anyTimes();
		expect(authorizationSession.isAuthorized(anyObject(), anyObject())).andReturn(true).anyTimes();
		expect(certificateProfileSession.getAllCertificateProfiles()).andReturn(Collections.emptyMap()).anyTimes();
		expect(globalConfigurationSession.getCachedConfiguration(anyString())).andReturn(new AvailableProtocolsConfiguration()).anyTimes();

		replay(externalContext, application, ejbcaJSFHelper, authenticationToken, authorizationSession, certificateProfileSession, globalConfigurationSession);

		setCurrentFacesContext(facesContext);
	}

	@Test
	public void testAddCustomCertExtension() throws Exception {
		// Given
		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(ejbcaWebBean.getText(anyString())).andAnswer(() -> (String) EasyMock.getCurrentArguments()[0]).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		ejbcaWebBean.saveAvailableCustomCertExtensionsConfiguration(anyObject(AvailableCustomCertificateExtensionsConfiguration.class));
		EasyMock.expectLastCall().once();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("1.2.3.4");
		systemConfigMBean.setNewDisplayName("TESTEXTENSION1");

		// When
		systemConfigMBean.addCustomCertExtension();

		// Expect
		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testAddCustomCertExtensionWithoutOid() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("");
		systemConfigMBean.setNewDisplayName("TESTEXTENSION1");

		// When
		systemConfigMBean.addCustomCertExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("No CustomCertificateExtension OID is set.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testAddCustomCertExtensionWithNonNumericOid() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("A.B.C.D");
		systemConfigMBean.setNewDisplayName("TESTEXTENSION1");

		// When
		systemConfigMBean.addCustomCertExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("OID A.B.C.D contains non-numerical values.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testAddCustomCertExtensionWithoutLabel() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("1.2.3.4");
		systemConfigMBean.setNewDisplayName("");

		// When
		systemConfigMBean.addCustomCertExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("No CustomCertificateExtension Label is set.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testAddCustomCertExtensionNonUniqueOid() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		replay(ejbcaWebBean, facesContext);

		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("1.2.3.4");
		systemConfigMBean.setNewDisplayName("TESTEXTENSION2");

		// When
		systemConfigMBean.addCustomCertExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("CustomCertificateExtension OID '1.2.3.4' already exists in the database.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testAddCustomCertExtensionNonUniqueLabel() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		replay(ejbcaWebBean, facesContext);

		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("2.2.3.4");
		systemConfigMBean.setNewDisplayName("TESTEXTENSION1");

		// When
		systemConfigMBean.addCustomCertExtension();

		// Expect
		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("CustomCertificateExtension Label 'TESTEXTENSION1' already exists in the database.", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	@Test
	public void testAddCustomCertExtensionError() throws Exception {
		// Given
		final Capture<FacesMessage> messageCapture = EasyMock.newCapture();

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		ejbcaWebBean.saveAvailableCustomCertExtensionsConfiguration(anyObject(AvailableCustomCertificateExtensionsConfiguration.class));
		EasyMock.expectLastCall().andThrow(new RuntimeException(""));

		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();
		facesContext.addMessage(isNull(), capture(messageCapture));
		EasyMock.expectLastCall().once();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("1.2.3.4");
		systemConfigMBean.setNewDisplayName("TESTEXTENSION1");

		// When
		systemConfigMBean.addCustomCertExtension();

		// Expect

		assertEquals(FacesMessage.SEVERITY_ERROR, messageCapture.getValue().getSeverity());
		assertEquals("Failed to add Custom Certificate Extension. ", messageCapture.getValue().getSummary());

		verify(ejbcaWebBean, facesContext);
	}

	// --------------------------------------------
	//
	// --------------------------------------------

	@Test
	public void testIsOidUnique() throws Exception {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("3.2.3.4");

		// When
		final boolean result = systemConfigMBean.isOidUnique(cceConfig);

		// Expect
		assertTrue("OID Should be unique", result);
	}

	@Test
	public void testIsOidNotUnique() throws Exception {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewOID("2.2.3.4");

		// When
		final boolean result = systemConfigMBean.isOidUnique(cceConfig);

		// Expect
		assertFalse("OID Should NOT be unique", result);
	}

	@Test
	public void testIsDisplayNameUnique() throws Exception {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
		systemConfigMBean.setNewDisplayName("TESTEXTENSION4");

		// When
		final boolean result = systemConfigMBean.isDisplayNameUnique(cceConfig);

		// Expect
		assertTrue("Display Name Should be unique", result);
	}

	@Test
	public void testIsDisplayNameNotUnique() throws Exception {
		// Given
		cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION1", BasicCertificateExtension.class.getName(), true, true, null);
		cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, null);

		expect(ejbcaWebBean.getEjb()).andReturn(ejbBridgeSession).anyTimes();
		expect(ejbcaWebBean.getAvailableCustomCertExtensionsConfiguration()).andReturn(cceConfig).anyTimes();
		expect(facesContext.getExternalContext()).andReturn(externalContext).anyTimes();
		expect(facesContext.getApplication()).andReturn(application).anyTimes();

		replay(ejbcaWebBean, facesContext);

		systemConfigMBean = new SystemConfigMBean();
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
