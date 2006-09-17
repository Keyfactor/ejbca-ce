package org.ejbca.core.protocol.ws;

import java.security.cert.CertificateEncodingException;

import org.ejbca.util.Base64;

public class Certificate {
	
	private byte[] certificateData = null;
	
	public Certificate(){
		
	}

	public Certificate(java.security.cert.Certificate cert) throws CertificateEncodingException{
		certificateData = Base64.encode(cert.getEncoded());
	}

	/**
	 * @return Returns the certificateData in Base64 encoded format
	 */
	public byte[] getCertificateData() {
		return certificateData;
	}

	/**
	 * @param certificateData The certificateData to set, in Base64 encoded format.
	 */
	public void setCertificateData(byte[] certificateData) {
		this.certificateData = certificateData;
	}

}
