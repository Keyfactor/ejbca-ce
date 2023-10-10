/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.crl;

import java.util.Objects;

/**
 * An expired CRL deletion DTO which holds all the necessary fields for a corresponding grouping and deletion itself
 * afterward.
 */
public class CrlMetadataHolderDto {

	private final String fingerprint;
	private final String issuerDN;
	private final int cRLNumber;
	private final int deltaCRLIndicator;
	private final long nextUpdate;

	public CrlMetadataHolderDto(String fingerprint, String issuerDN, int cRLNumber, int deltaCRLIndicator, long nextUpdate) {
		this.fingerprint = fingerprint;
		this.issuerDN = issuerDN;
		this.cRLNumber = cRLNumber;
		this.deltaCRLIndicator = deltaCRLIndicator;
		this.nextUpdate = nextUpdate;
	}

	public String getFingerprint() {
		return fingerprint;
	}

	public String getIssuerDN() {
		return issuerDN;
	}

	public int getcRLNumber() {
		return cRLNumber;
	}

	public int getDeltaCRLIndicator() {
		return deltaCRLIndicator;
	}

	public long getNextUpdate() {
		return nextUpdate;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		CrlMetadataHolderDto that = (CrlMetadataHolderDto) o;
		return cRLNumber == that.cRLNumber && deltaCRLIndicator == that.deltaCRLIndicator
				&& nextUpdate == that.nextUpdate && Objects.equals(fingerprint,
				that.fingerprint) && Objects.equals(issuerDN, that.issuerDN);
	}

	@Override
	public int hashCode() {
		return Objects.hash(fingerprint, issuerDN, cRLNumber, deltaCRLIndicator, nextUpdate);
	}
}
