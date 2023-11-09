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
package org.ejbca.core.protocol.ocsp;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.cesecore.certificates.certificateprofile.CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
import static org.cesecore.certificates.endentity.EndEntityConstants.EMPTY_END_ENTITY_PROFILE;
import static org.ejbca.core.model.token.TokenConstants.REQUESTTYPE_KEYSTORE_REQUEST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PreSigningOcspResponseSystemTest extends CaTestCase {

	private static final String TEST_CERTIFICATE_USERNAME = "shouldPreSignOcspResponse";
	private static final String TEST_CERTIFICATE_PASSWORD = "foo123";
	private static final String CA_NAME = "CertExpNotifCA";
	private static final String DEFAULT_CA_DN = "CN=" + CA_NAME;
	private static final String DEFAULT_CERT_DN = "CN=shouldPreSignOcspResponse";

	private X509CA x509ca;

	private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("PreSigningOcspResponseTest"));
	private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
	private final SignSessionRemote signSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
	private final RevocationSessionRemote revocationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RevocationSessionRemote.class);
	private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
			.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
	private final CertificateStoreSessionRemote certificateStoreSessionRemote = EjbRemoteHelper.INSTANCE
			.getRemoteSession(CertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
	private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
	private OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
			.getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
	private OcspJunitHelper ocspJunitHelper;

	@BeforeClass
	public static void beforeClass() throws Exception {
		CryptoProviderTools.installBCProvider();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		addDefaultRole();

		x509ca = CaTestUtils.createTestX509CAOptionalGenKeys(DEFAULT_CA_DN, TEST_CERTIFICATE_PASSWORD.toCharArray(), true,
				false, "1024", X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
		caSession.addCA(admin, x509ca);
		certificateStoreSessionRemote.storeCertificateRemote(admin, EJBTools.wrap(x509ca.getCACertificate()),
				"SYSTEMCA",
				CertTools.getFingerprintAsString(x509ca.getCACertificate()),
				CertificateConstants.CERT_ACTIVE,
				CertificateConstants.CERTTYPE_ROOTCA,
				CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
				EMPTY_END_ENTITY_PROFILE,
				CertificateConstants.NO_CRL_PARTITION,
				null, System.currentTimeMillis(), null);

		EndEntityInformation endEntity = new EndEntityInformation();
		endEntity.setUsername(TEST_CERTIFICATE_USERNAME);
		endEntity.setPassword(TEST_CERTIFICATE_PASSWORD);
		endEntity.setCAId(x509ca.getCAId());
		endEntity.setCertificateProfileId(CERTPROFILE_FIXED_ENDUSER);
		endEntity.setEndEntityProfileId(EMPTY_END_ENTITY_PROFILE);
		endEntity.setDN(DEFAULT_CERT_DN);
		endEntity.setTokenType(REQUESTTYPE_KEYSTORE_REQUEST);
		endEntity.setType(new EndEntityType(EndEntityTypes.ENDUSER));

		endEntityManagementSession.addUser(admin, endEntity, false);
		final String remoteHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
		final String remotePort = SystemTestsConfiguration.getRemotePortHttp("8080");
		ocspJunitHelper = new OcspJunitHelper("http://" + remoteHost + ":" + remotePort + "/ejbca",
				"publicweb/status/ocsp");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		removeDefaultRole();
		endEntityManagementSession.deleteUser(admin, TEST_CERTIFICATE_USERNAME);
		internalCertificateStoreSession.removeCertificatesByUsername(TEST_CERTIFICATE_USERNAME);
		caSession.removeCA(admin, x509ca.getCAId());
		internalCertificateStoreSession.removeCertificate(x509ca.getCACertificate());
	}

	@Test
	public void shouldPreSignOcspResponse() throws AuthorizationDeniedException, InvalidAlgorithmParameterException,
			CustomCertificateSerialNumberException, NoSuchEndEntityException, CryptoTokenOfflineException,
			AuthStatusException, CertificateSerialNumberException, AuthLoginException, IllegalKeyException,
			CAOfflineException, CertificateRevokeException, CADoesntExistsException, InvalidAlgorithmException,
			CertificateCreateException, IllegalValidityException, IllegalNameException, OCSPException,
			CertificateException, IOException, NoSuchProviderException, OperatorCreationException,
			NoSuchAlgorithmException {

		KeyPair anotherKey = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);

		X509Certificate certificate = (X509Certificate) signSessionRemote.createCertificate(admin,
				TEST_CERTIFICATE_USERNAME,
				TEST_CERTIFICATE_PASSWORD,
				new PublicKeyWrapper(anotherKey.getPublic()), -1, null, null,
				CERTPROFILE_FIXED_ENDUSER, SecConst.CAID_USEUSERDEFINED);

		ocspResponseGeneratorTestSession.reloadOcspSigningCache();

		OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
		ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(),
				(X509Certificate) x509ca.getCACertificate(), certificate.getSerialNumber()));

		OCSPReq ocspReq = ocspReqBuilder.build();

		SingleResp basicOCSPResp = ocspJunitHelper.sendOCSPPost(ocspReq.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200)[0];
		assertEquals(CertificateStatus.GOOD, basicOCSPResp.getCertStatus());

		revocationSessionRemote.revokeCertificate(admin, certificate, null, null, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, null);
		BasicOCSPResp revokedCertOcspResponse = ocspJunitHelper.sendOCSPGet(ocspReq.getEncoded(), null,
				OCSPRespBuilder.SUCCESSFUL, 200);
		assertTrue(revokedCertOcspResponse.getResponses()[0].getCertStatus() instanceof RevokedStatus);
	}

	@Override
	public String getRoleName() {
		return "PreSigningOcspResponseTest";
	}
}
