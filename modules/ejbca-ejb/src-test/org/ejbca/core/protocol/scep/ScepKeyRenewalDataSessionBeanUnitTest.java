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
package org.ejbca.core.protocol.scep;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.easymock.EasyMock;
import org.ejbca.config.ScepConfiguration;
import org.junit.Test;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.Period;
import java.util.Date;
import java.util.Set;

import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.ejbca.util.SimpleMock.inject;

public class ScepKeyRenewalDataSessionBeanUnitTest {

	private final static String TEST_SCEP_ALIAS = "test_scep_alias";

	@Test
	public void testRenewScepKeysNoAliasSuccess() {
		var scepKeyRenewalDataSessionBean = new ScepKeyRenewalDataSessionBean();
		final GlobalConfigurationSessionLocal globalConfigSessionMock = EasyMock.createMock(
				GlobalConfigurationSessionLocal.class);
		final ScepConfiguration scepConfigurationMock = EasyMock.createMock(ScepConfiguration.class);
		expect(globalConfigSessionMock.getCachedConfigurationAndLockWrites(anyString())).andReturn(
				scepConfigurationMock);
		expect(scepConfigurationMock.getAliasList()).andReturn(Set.of());
		inject(scepKeyRenewalDataSessionBean, "globalConfigSession", globalConfigSessionMock);
		replay(globalConfigSessionMock, scepConfigurationMock);

		scepKeyRenewalDataSessionBean.renewScepKeys();

		verify(globalConfigSessionMock, scepConfigurationMock);
	}

	@Test
	public void testRenewScepKeysAliasNoKeysSuccess() {
		var scepKeyRenewalDataSessionBean = new ScepKeyRenewalDataSessionBean();
		final ScepConfiguration scepConfigurationMock = EasyMock.createMock(ScepConfiguration.class);
		expect(scepConfigurationMock.getAliasList()).andReturn(Set.of(TEST_SCEP_ALIAS));
		expect(scepConfigurationMock.decodeEncryptionCertificate(TEST_SCEP_ALIAS)).andReturn(null);
		expect(scepConfigurationMock.decodeSigningCertificate(TEST_SCEP_ALIAS)).andReturn(null);
		final GlobalConfigurationSessionLocal globalConfigSessionMock = EasyMock.createMock(
				GlobalConfigurationSessionLocal.class);
		expect(globalConfigSessionMock.getCachedConfigurationAndLockWrites(anyString())).andReturn(
				scepConfigurationMock);
		inject(scepKeyRenewalDataSessionBean, "globalConfigSession", globalConfigSessionMock);
		replay(globalConfigSessionMock, scepConfigurationMock);

		scepKeyRenewalDataSessionBean.renewScepKeys();

		verify(globalConfigSessionMock, scepConfigurationMock);
	}

	@Test
	public void testRenewScepKeysStillValidSuccess() {
		var scepKeyRenewalDataSessionBean = new ScepKeyRenewalDataSessionBean();
		final X509Certificate encryptCertficateMock = EasyMock.createMock(X509Certificate.class);
		expect(encryptCertficateMock.getNotAfter()).andReturn(Date.from(Instant.now().plus(Period.ofDays(30))));
		final X509Certificate signingCertificateMock = EasyMock.createMock(X509Certificate.class);
		expect(signingCertificateMock.getNotAfter()).andReturn(Date.from(Instant.now().plus(Period.ofDays(30))));
		final ScepConfiguration scepConfigurationMock = EasyMock.createMock(ScepConfiguration.class);
		expect(scepConfigurationMock.getAliasList()).andReturn(Set.of(TEST_SCEP_ALIAS));
		expect(scepConfigurationMock.decodeEncryptionCertificate(TEST_SCEP_ALIAS)).andReturn(encryptCertficateMock);
		expect(scepConfigurationMock.decodeSigningCertificate(TEST_SCEP_ALIAS)).andReturn(signingCertificateMock);
		final GlobalConfigurationSessionLocal globalConfigSessionMock = EasyMock.createMock(
				GlobalConfigurationSessionLocal.class);
		expect(globalConfigSessionMock.getCachedConfigurationAndLockWrites(anyString())).andReturn(
				scepConfigurationMock);
		inject(scepKeyRenewalDataSessionBean, "globalConfigSession", globalConfigSessionMock);
		replay(globalConfigSessionMock, scepConfigurationMock, encryptCertficateMock, signingCertificateMock);

		scepKeyRenewalDataSessionBean.renewScepKeys();

		verify(globalConfigSessionMock, scepConfigurationMock, encryptCertficateMock, signingCertificateMock);
	}

	@Test
	public void testRenewScepKeysSuccess()
			throws AuthorizationDeniedException, ScepEncryptionCertificateIssuanceException,
			CertificateEncodingException {
		var scepKeyRenewalDataSessionBean = new ScepKeyRenewalDataSessionBean();
		final X509Certificate encryptCertificateMock = EasyMock.createMock(X509Certificate.class);
		expect(encryptCertificateMock.getNotAfter()).andReturn(Date.from(Instant.now())).times(2);
		expect(encryptCertificateMock.getSubjectDN()).andReturn(null);
		expect(encryptCertificateMock.getSerialNumber()).andReturn(BigInteger.ZERO);
		final X509Certificate signingCertificateMock = EasyMock.createMock(X509Certificate.class);
		expect(signingCertificateMock.getNotAfter()).andReturn(Date.from(Instant.now())).times(2);
		expect(signingCertificateMock.getSubjectDN()).andReturn(null);
		expect(signingCertificateMock.getSerialNumber()).andReturn(BigInteger.ZERO);
		final ScepConfiguration scepConfigurationMock = EasyMock.createMock(ScepConfiguration.class);
		expect(scepConfigurationMock.getAliasList()).andReturn(Set.of(TEST_SCEP_ALIAS));
		expect(scepConfigurationMock.decodeEncryptionCertificate(TEST_SCEP_ALIAS)).andReturn(encryptCertificateMock);
		expect(scepConfigurationMock.decodeSigningCertificate(TEST_SCEP_ALIAS)).andReturn(signingCertificateMock);
		expect(scepConfigurationMock.getRADefaultCA(TEST_SCEP_ALIAS)).andReturn("").times(2);
		expect(scepConfigurationMock.getEncryptionCryptoTokenId(TEST_SCEP_ALIAS)).andReturn(0);
		expect(scepConfigurationMock.getEncryptionKeyAlias(TEST_SCEP_ALIAS)).andReturn("");
		expect(scepConfigurationMock.getSigningCryptoTokenId(TEST_SCEP_ALIAS)).andReturn(0);
		expect(scepConfigurationMock.getSigningKeyAlias(TEST_SCEP_ALIAS)).andReturn("");
		scepConfigurationMock.setEncryptionCertificate(eq(TEST_SCEP_ALIAS), anyString());
		expectLastCall().once();
		scepConfigurationMock.setSigningCertificate(eq(TEST_SCEP_ALIAS), anyString());
		expectLastCall().once();
		final GlobalConfigurationSessionLocal globalConfigSessionMock = EasyMock.createMock(
				GlobalConfigurationSessionLocal.class);
		expect(globalConfigSessionMock.getCachedConfigurationAndLockWrites(anyString())).andReturn(
				scepConfigurationMock);
		globalConfigSessionMock.saveConfiguration(anyObject(), anyObject());
		expectLastCall().once();
		final X509Certificate encryptCertificateRenewedMock = EasyMock.createMock(X509Certificate.class);
		encryptCertificateRenewedMock.getEncoded();
		expectLastCall().andReturn(new byte[0]).once();
		expect(encryptCertificateRenewedMock.getNotAfter()).andReturn(Date.from(Instant.now()));
		expect(encryptCertificateRenewedMock.getSubjectDN()).andReturn(null);
		expect(encryptCertificateRenewedMock.getSerialNumber()).andReturn(BigInteger.ZERO);
		final X509Certificate signingCertificateRenewedMock = EasyMock.createMock(X509Certificate.class);
		signingCertificateRenewedMock.getEncoded();
		expectLastCall().andReturn(new byte[0]).once();
		expect(signingCertificateRenewedMock.getNotAfter()).andReturn(Date.from(Instant.now()));
		expect(signingCertificateRenewedMock.getSubjectDN()).andReturn(null);
		expect(signingCertificateRenewedMock.getSerialNumber()).andReturn(BigInteger.ZERO);
		final ScepRaCertificateIssuer scepRaCertificateIssuerMock = EasyMock.createMock(ScepRaCertificateIssuer.class);
		expect(scepRaCertificateIssuerMock.issueEncryptionCertificate(anyObject(), anyString(), anyInt(),
				anyString())).andReturn(encryptCertificateRenewedMock);
		expect(scepRaCertificateIssuerMock.issueSigningCertificate(anyObject(), anyString(), anyInt(),
				anyString())).andReturn(signingCertificateRenewedMock);
		inject(scepKeyRenewalDataSessionBean, "globalConfigSession", globalConfigSessionMock);
		inject(scepKeyRenewalDataSessionBean, "scepRaCertificateIssuer", scepRaCertificateIssuerMock);
		replay(globalConfigSessionMock, scepConfigurationMock, encryptCertificateMock, signingCertificateMock,
				scepRaCertificateIssuerMock, encryptCertificateRenewedMock, signingCertificateRenewedMock);

		scepKeyRenewalDataSessionBean.renewScepKeys();

		verify(globalConfigSessionMock, scepConfigurationMock, encryptCertificateMock, signingCertificateMock,
				scepRaCertificateIssuerMock, encryptCertificateRenewedMock, signingCertificateRenewedMock);
	}

}
