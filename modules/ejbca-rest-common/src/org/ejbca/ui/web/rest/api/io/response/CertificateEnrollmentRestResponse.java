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
package org.ejbca.ui.web.rest.api.io.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.keyfactor.util.CertTools;
import io.swagger.annotations.ApiModelProperty;
import org.ejbca.core.model.SecConst;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A class responsible for representing the certificate enrollment result.
 */
public class CertificateEnrollmentRestResponse {

	private static final String DER_RESPONSE_FORMAT = "DER";

	@ApiModelProperty(value = "Certificate", example = "MIIDXzCCA...eW1Zro0=")
	private final byte[] certificate;

	@ApiModelProperty(value = "Hex Serial Number", example = "1234567890ABCDEF")
	@JsonInclude(JsonInclude.Include.NON_NULL)
	private final String serialNumber;

	@ApiModelProperty(value = "Response format", example = "DER")
	private final String responseFormat;

	@ApiModelProperty(value = "Certificate chain", example = "[\"ABC123efg...345xyz0=\"]")
	private final List<byte[]> certificateChain;

	private CertificateEnrollmentRestResponse(final CertificateRestResponseBuilder builder) {
		this.certificate = builder.certificate;
		this.serialNumber = builder.serialNumber;
		this.responseFormat = builder.responseFormat;
		this.certificateChain = builder.certificateChain;
	}

	/**
	 * Return a builder instance for this class.
	 *
	 * @return builder instance for this class.
	 */
	public static CertificateRestResponseBuilder builder() {
		return new CertificateRestResponseBuilder();
	}

	public byte[] getCertificate() {
		return certificate;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public String getResponseFormat() {
		return responseFormat;
	}

	public List<byte[]> getCertificateChain() {
		return certificateChain;
	}

	public static CertificateRestResponseConverter converter() {
		return new CertificateRestResponseConverter();
	}

	public static class CertificateRestResponseBuilder {

		private byte[] certificate;
		private String serialNumber;
		private String responseFormat;
		private List<byte[]> certificateChain;

		private CertificateRestResponseBuilder() {
		}

		public CertificateRestResponseBuilder setCertificate(byte[] certificate) {
			this.certificate = certificate;
			return this;
		}

		public CertificateRestResponseBuilder setSerialNumber(String serialNumber) {
			this.serialNumber = serialNumber;
			return this;
		}

		public CertificateRestResponseBuilder setResponseFormat(String responseFormat) {
			this.responseFormat = responseFormat;
			return this;
		}

		public CertificateRestResponseBuilder setResponseFormat(int keystoreType) {
			switch (keystoreType) {
			case SecConst.TOKEN_SOFT_JKS:
				this.responseFormat = "JKS";
				break;
			case SecConst.TOKEN_SOFT_PEM:
				this.responseFormat = "PEM";
				break;
			case SecConst.TOKEN_SOFT_P12:
			case SecConst.TOKEN_SOFT_BROWSERGEN:
				this.responseFormat = "PKCS12";
				break;
			case SecConst.TOKEN_SOFT_BCFKS:
				this.responseFormat = "BCFKS";
				break;
			default:
				this.responseFormat = "UNKNOWN";
				break;
			}
			return this;
		}

		public CertificateRestResponseBuilder setCertificateChain(final List<byte[]> certificateChain) {
			this.certificateChain = certificateChain;
			return this;
		}

		public CertificateEnrollmentRestResponse build() {
			return new CertificateEnrollmentRestResponse(this);
		}
	}

	public static class CertificateRestResponseConverter {

		public CertificateEnrollmentRestResponse toRestResponse(final byte[] certificate, String serialNumber, final List<Certificate> certificateChain)  {
			return createCertificateRestResponse(certificate, serialNumber, certificateChain);
		}

		public CertificateEnrollmentRestResponse toRestResponse(final Certificate certificate, final List<Certificate> certificateChain) {
			return createCertificateRestResponse(
					getEncodedCertificate(certificate),
					CertTools.getSerialNumberAsString(certificate),
					certificateChain
			);
		}

		private static CertificateEnrollmentRestResponse createCertificateRestResponse(final byte[] certificate,
				String serialNumber, List<Certificate> certificateChain) {
			return CertificateEnrollmentRestResponse.builder()
					.setCertificate(certificate)
					.setSerialNumber(serialNumber)
					.setCertificateChain(certificateChain == null
									? null
									: encodeChainCertificates(certificateChain))
					.setResponseFormat(DER_RESPONSE_FORMAT)
					.build();
		}

		private static List<byte[]> encodeChainCertificates(List<Certificate> certificateChain) {
			return certificateChain
					.stream()
					.map(CertificateRestResponseConverter::getEncodedCertificate)
					.collect(Collectors.toList());
		}

		private static byte[] getEncodedCertificate(final Certificate certificate) {
			try {
				return certificate.getEncoded();
			} catch (CertificateEncodingException e) {
				throw new IllegalStateException(
						"Unable to encode certificate of the following type=" + certificate.getType(), e);
			}
		}
	}
}
