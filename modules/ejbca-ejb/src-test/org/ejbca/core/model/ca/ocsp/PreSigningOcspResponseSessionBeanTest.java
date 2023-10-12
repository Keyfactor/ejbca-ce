/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ca.ocsp;

import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateData;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;
import org.ejbca.core.ejb.ocsp.PreSigningOcspResponseSessionBean;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.cesecore.certificates.certificate.CertificateConstants.DEFAULT_CERTID_HASH_ALGORITHM;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

/**
 * Unit test for {@link PreSigningOcspResponseSessionBean}
 */
@RunWith(EasyMockRunner.class)
public class PreSigningOcspResponseSessionBeanTest {

	private static final String SERIAL_NUMBER = "123";

	@Mock
	private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;

	@TestSubject
	private final PreSigningOcspResponseSessionBean testInstance = new PreSigningOcspResponseSessionBean();

	@Test
	public void shouldProcessOcspResponseWhenCertificateChainIsNotEmpty() {
		//given
		BaseCertificateData certData = new CertificateData();
		certData.setSerialNumber(SERIAL_NUMBER);
		X509Certificate certificate = mock(X509Certificate.class);
		ocspResponseGeneratorSession.preSignOcspResponse(eq(certificate), eq(new BigInteger(SERIAL_NUMBER)), eq(true),
				eq(true), eq(DEFAULT_CERTID_HASH_ALGORITHM));
		expectLastCall();
		replay(ocspResponseGeneratorSession);

		X509CA ca = createMock(X509CA.class);
		expect(ca.isDoPreProduceOcspResponses()).andReturn(true);
		expect(ca.getCertificateChain()).andReturn(Collections.singletonList(certificate));
		replay(ca);

		//when
		testInstance.preSignOcspResponse(ca, certData);

		//then
		verify(ocspResponseGeneratorSession);
	}

	@Test(expected = IllegalStateException.class)
	public void shouldProcessOcspResponseWhenCertificateChainIsEmpty() {
		//given
		BaseCertificateData certData = new CertificateData();
		certData.setSerialNumber(SERIAL_NUMBER);

		X509CA ca = createMock(X509CA.class);
		expect(ca.isDoPreProduceOcspResponses()).andReturn(true);
		expect(ca.getCertificateChain()).andReturn(Collections.emptyList());
		replay(ca);

		//when
		testInstance.preSignOcspResponse(ca, certData);

		//then
		verify(ocspResponseGeneratorSession);
	}

	@Test(expected = IllegalStateException.class)
	public void shouldDoNothingWhenNoOcspResponseProductionChosen() {
		//given
		BaseCertificateData certData = new CertificateData();
		certData.setSerialNumber(SERIAL_NUMBER);

		X509CA ca = createMock(X509CA.class);
		expect(ca.isDoPreProduceOcspResponses()).andReturn(false);
		expect(ca.getCertificateChain()).andReturn(Collections.emptyList());
		replay(ca);

		//when
		testInstance.preSignOcspResponse(ca, certData);

		//then
		verify(ocspResponseGeneratorSession);
	}
}
