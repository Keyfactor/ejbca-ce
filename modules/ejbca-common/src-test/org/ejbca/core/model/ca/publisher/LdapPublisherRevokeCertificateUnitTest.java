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
package org.ejbca.core.model.ca.publisher;

import com.keyfactor.util.CertTools;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPModification;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.createMockBuilder;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.easymock.EasyMock.verifyUnexpectedCalls;
import static org.junit.Assert.assertEquals;

/**
 * Unit tests for {@link LdapPublisher}
 */
public class LdapPublisherRevokeCertificateUnitTest {
	private static final byte[] CERTIFICATE = """
            -----BEGIN CERTIFICATE-----
            MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE
            AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw
            ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD
            VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB
            hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy
            Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe
            ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G
            A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM
            MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw
            GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS
            5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c
            UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+
            XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==
            -----END CERTIFICATE-----
            """.getBytes(StandardCharsets.UTF_8);

	private static final byte[] OTHER_CERTIFICATE = """
            -----BEGIN CERTIFICATE-----
            MIICcjCCAVqgAwIBAgIUXRQWxgdQvHoxJu0gJajoa9CKLFswDQY
            JKoZIhvcNAQELBQAwPTEPMA0GA1UEAwwGbGRhcGNhMRMwEQYKCZImiZPyLGQBGRYDbGFiMRUwEw
            YKCZImiZPyLGQBGRYFbG9jYWwwHhcNMjYwMzE4MDkwMDUwWhcNMjgwMzE3MDkwMDQ5WjAMMQowC
            AYDVQQDDAFjMEAwEAYHKoZIzj0CAQYFK4EEAA8DLAAEA0gNABag+uBhiKdmjaksw7QXsnR/BNVd
            ysPbvBPuQqXKnq+n7f6erh0/o38wfTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFNOwwoFfJLP
            1BdljbWKpBaEWEYLoMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAdBgNVHQ4EFgQUxr
            u+QMgh5/wkY2tAPcr7rYsgmn4wDgYDVR0PAQH/BAQDAgbAMA0GCSqGSIb3DQEBCwUAA4IBAQAY0
            2o3o+ychn7V0yrfCK25yIIn27DbylgYeIQ5G5tkLabX2zToj0YhF7mTCzdwkzpHj+zJipISWl7k
            8S1gvKGAxOIALyWGwT8JFiNYbyqqTvn/Xdbf8gkELtyhK43yolXoLVu0sN4858KugJB1MJyitP/
            i7UhjRzuilcr5OHgRy1WgIwXxrwfOelWrQAKTvg6KUTIqK6yQU6E9RU6aeGJ1OyyEYL2ZrW0/tz
            IzLyptUoiODiLDqpdxdPeim2WPDh9TkIrcYGHF6xuopfTr5Vi4qlmNBOyr8cwNqZrvdPmADhKwZ
            0HJHBAoFWdVOYh8e0mJi9HjyQrKb8RBwHx6g1gH
            -----END CERTIFICATE-----
            """.getBytes(StandardCharsets.UTF_8);

    private LdapPublisher testClass;
	private AuthenticationToken authenticationToken;
	private LDAPConnection ldapConnection;

	@Before
	public void setUp() throws Exception {
		//
		testClass = createMockBuilder(LdapPublisher.class)
				.withConstructor()
				.addMockedMethod("createLdapConnection")
				.addMockedMethod("searchOldEntity")
				.addMockedMethod("probeAndConnectLdapServer")
				.createMock();
		testClass.setConnectionSecurity(LdapPublisher.ConnectionSecurity.SSL);

		authenticationToken = EasyMock.createMock(AuthenticationToken.class);
		ldapConnection = EasyMock.createMock(LDAPConnection.class);
	}

	private void setupLdapConnection() throws Exception {
		expect(testClass.createLdapConnection()).andReturn(ldapConnection);

		testClass.probeAndConnectLdapServer(anyString(), anyObject(LDAPConnection.class));
		EasyMock.expectLastCall().once();

		ldapConnection.bind(anyInt(), anyString(), anyObject(byte[].class), anyObject(LDAPConstraints.class));
		EasyMock.expectLastCall().once();
		ldapConnection.disconnect(anyObject(LDAPConstraints.class));
		EasyMock.expectLastCall().once();
	}

    @Test
    public void shouldRemoveOnlyCertificateFromLdap() throws Exception {
		// GIVEN
		final Certificate cert = CertTools.getCertfromByteArray(CERTIFICATE, Certificate.class);
		final String username = "test 1";
		final int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
		final String userDN = "CN=test 1,O=Test Org,C=SE";
		final LDAPEntry	fromLdap = getLdapUserEntryWithCertificate(userDN);

		setupLdapConnection();
		expect(testClass.searchOldEntity(eq(username), eq(LDAPConnection.LDAP_V3), eq(ldapConnection), anyString(), anyString(), anyString())).andReturn(fromLdap);

		final Capture<LDAPModification[]> modifications = EasyMock.newCapture();
		ldapConnection.modify(eq(userDN), capture(modifications), anyObject(LDAPConstraints.class));
		EasyMock.expectLastCall().once();

		replay(testClass);
		replay(ldapConnection);

		// WHEN
		testClass.revokeCertificate(authenticationToken, cert, username, reason, userDN);

		// THEN
		verify(testClass, ldapConnection);
		verifyUnexpectedCalls(testClass, ldapConnection);

		final LDAPModification[] executedModifications = modifications.getValue();
		assertEquals(1, executedModifications.length);
		assertEquals(LDAPModification.DELETE, executedModifications[0].getOp());
		assertEquals(testClass.getUserCertAttribute(), executedModifications[0].getAttribute().getName());
	}

	@Test
	public void shouldRemoveUserAndCertificateFromLdap() throws Exception {
		// GIVEN
		final Certificate cert = CertTools.getCertfromByteArray(CERTIFICATE, Certificate.class);
		final String username = "test 2";
		final int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
		final String userDN = "CN=test 2,O=Test Org,C=SE";
		final LDAPEntry	fromLdap = getLdapUserEntryWithCertificate(userDN);
		testClass.setRemoveUsersWhenCertRevoked(true);

		setupLdapConnection();
		expect(testClass.searchOldEntity(eq(username), eq(LDAPConnection.LDAP_V3), eq(ldapConnection), anyString(), anyString(), anyString())).andReturn(fromLdap);

		final Capture<LDAPModification[]> modifications = EasyMock.newCapture();
		ldapConnection.modify(eq(userDN), capture(modifications), anyObject(LDAPConstraints.class));
		EasyMock.expectLastCall().once();
		ldapConnection.delete(eq(userDN), anyObject(LDAPConstraints.class));
		EasyMock.expectLastCall().once();

		replay(testClass);
		replay(ldapConnection);

		// WHEN
		testClass.revokeCertificate(authenticationToken, cert, username, reason, userDN);

		// THEN
		verify(testClass, ldapConnection);
		verifyUnexpectedCalls(testClass, ldapConnection);

		final LDAPModification[] executedModifications = modifications.getValue();
		assertEquals(1, executedModifications.length);
		assertEquals(LDAPModification.DELETE, executedModifications[0].getOp());
		assertEquals(testClass.getUserCertAttribute(), executedModifications[0].getAttribute().getName());
	}

	@Test
	public void shouldNotRemoveCertificateIfDoesNotExists() throws Exception {
		// GIVEN
		final Certificate cert = CertTools.getCertfromByteArray(CERTIFICATE, Certificate.class);
		final String username = "test 3";
		final int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
		final String userDN = "CN=test 3,O=Test Org,C=SE";
		final LDAPEntry	fromLdap = getLdapUserEntryWithOtherCertificate(userDN);

		setupLdapConnection();

		expect(testClass.searchOldEntity(eq(username), eq(LDAPConnection.LDAP_V3), eq(ldapConnection), anyString(), anyString(), anyString())).andReturn(fromLdap);

		replay(testClass);
		replay(ldapConnection);

		// WHEN
		testClass.revokeCertificate(authenticationToken, cert, username, reason, userDN);

		// THEN
		verify(testClass, ldapConnection);
		verifyUnexpectedCalls(testClass, ldapConnection);
	}

	@Test
	public void shouldNotRemoveCertificateIfUserDoesNotExists() throws Exception {
		// GIVEN
		final Certificate cert = CertTools.getCertfromByteArray(CERTIFICATE, Certificate.class);
		final String username = "test 4";
		final int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
		final String userDN = "CN=test 4,O=Test Org,C=SE";
		final LDAPEntry	fromLdap = null;

		testClass.setRemoveUsersWhenCertRevoked(true);
		expect(testClass.createLdapConnection()).andReturn(ldapConnection);
		expect(testClass.searchOldEntity(eq(username), eq(LDAPConnection.LDAP_V3), eq(ldapConnection), anyString(), anyString(), anyString())).andReturn(fromLdap);

		replay(testClass);
		replay(ldapConnection);

		// WHEN
		testClass.revokeCertificate(authenticationToken, cert, username, reason, userDN);

		// THEN
		verify(testClass, ldapConnection);
		verifyUnexpectedCalls(testClass, ldapConnection);
	}

	@Test
	public void shouldSkipAllLdapChanges() throws Exception {
		// GIVEN
		final Certificate cert = CertTools.getCertfromByteArray(CERTIFICATE, Certificate.class);
		final String username = "test 5";
		final int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
		final String userDN = "CN=test 5,O=Test Org,C=SE";
		testClass.setRemoveRevokedCertificates(false);

		replay(testClass);
		replay(ldapConnection);

		// WHEN
		testClass.revokeCertificate(authenticationToken, cert, username, reason, userDN);

		// THEN
		verify(testClass, ldapConnection);
		verifyUnexpectedCalls(testClass, ldapConnection);

	}

	private LDAPEntry getLdapUserEntryWithCertificate(final String userDN) throws CertificateParsingException, CertificateEncodingException {
		final LDAPAttributeSet attributes = new LDAPAttributeSet();
		final Certificate cert = CertTools.getCertfromByteArray(CERTIFICATE, Certificate.class);
		attributes.add(new LDAPAttribute("userCertificate;binary", cert.getEncoded()));
		return new LDAPEntry(userDN, attributes);
	}

	private LDAPEntry getLdapUserEntryWithoutCertificate(final String userDN) {
		final LDAPAttributeSet attributes = new LDAPAttributeSet();
		return new LDAPEntry(userDN, attributes);
	}

	private LDAPEntry getLdapUserEntryWithOtherCertificate(final String userDN) throws CertificateParsingException, CertificateEncodingException {
		final LDAPAttributeSet attributes = new LDAPAttributeSet();
		final Certificate cert = CertTools.getCertfromByteArray(OTHER_CERTIFICATE, Certificate.class);
		attributes.add(new LDAPAttribute("userCertificate;binary", cert.getEncoded()));
		return new LDAPEntry(userDN, attributes);
	}

}
