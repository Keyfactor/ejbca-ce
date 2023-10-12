/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.util.cert;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.util.LogRedactionUtils;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class CertificateUtils {

	private CertificateUtils() {
	}

	private static final Logger log = Logger.getLogger(CertificateUtils.class);

	/** @return the CertificateID's based on the provided certificate */
	public static List<CertificateID> getIdFromCertificate(final X509Certificate certificate) {
		try {
			if (log.isTraceEnabled()) {
				log.trace("Building CertificateId's from certificate with subjectDN '" + LogRedactionUtils.getSubjectDnLogSafe(certificate) + "'.");
			}
			List<CertificateID> ret = new ArrayList<>();
			ret.add(createJcaCertificateID(OIWObjectIdentifiers.idSHA1, certificate));
			ret.add(createJcaCertificateID(NISTObjectIdentifiers.id_sha256, certificate));
			ret.add(createJcaCertificateID(NISTObjectIdentifiers.id_sha384, certificate));
			ret.add(createJcaCertificateID(NISTObjectIdentifiers.id_sha512, certificate));
			return ret;
		} catch (OCSPException | CertificateEncodingException | OperatorCreationException e) {
			throw new OcspFailureException(e);
		}
	}

	private static JcaCertificateID createJcaCertificateID(ASN1ObjectIdentifier idSha, X509Certificate certificate)
			throws OperatorCreationException, OCSPException, CertificateEncodingException {
		return new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(idSha)), certificate, certificate.getSerialNumber());
	}
}
