package org.ejbca.core.protocol.ocsp;

import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;

public class OCSPResponseItem {
	private CertificateID       certID;
	private CertificateStatus   certStatus;

	public OCSPResponseItem(CertificateID certID, CertificateStatus certStatus) {
		this.certID = certID;
		this.certStatus = certStatus;
	}

	public CertificateID getCertID() {
		return certID;
	}

	public CertificateStatus getCertStatus() {
		return certStatus;
	}
}
