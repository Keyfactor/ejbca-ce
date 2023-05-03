/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c); PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.resource.util;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;

public class TestEndEntityParamHolder {

	private final String testUsername;
	private final String testCertProfileName;
	private final String testEeProfileName;
	private final AuthenticationToken internalAdminToken;
	private final X509CA x509TestCa;
	private final EndEntityProfileSessionRemote endEntityProfileSessionRemote;
	private final CertificateProfileSessionRemote certificateProfileSession;
	private final EndEntityManagementSessionRemote endEntityManagementSession;

	private TestEndEntityParamHolder(Builder builder) {
		this.testUsername = builder.testUsername;
		this.testCertProfileName = builder.testCertProfileName;
		this.testEeProfileName = builder.testEeProfileName;
		this.internalAdminToken = builder.internalAdminToken;
		this.x509TestCa = builder.x509TestCa;
		this.endEntityProfileSessionRemote = builder.endEntityProfileSessionRemote;
		this.certificateProfileSession = builder.certificateProfileSession;
		this.endEntityManagementSession = builder.endEntityManagementSession;
	}

	public static Builder newBuilder() {
		return new Builder();
	}

	public String getTestUsername() {
		return testUsername;
	}

	public String getTestCertProfileName() {
		return testCertProfileName;
	}

	public String getTestEeProfileName() {
		return testEeProfileName;
	}

	public AuthenticationToken getInternalAdminToken() {
		return internalAdminToken;
	}

	public X509CA getX509TestCa() {
		return x509TestCa;
	}

	public EndEntityProfileSessionRemote getEndEntityProfileSessionRemote() {
		return endEntityProfileSessionRemote;
	}

	public CertificateProfileSessionRemote getCertificateProfileSession() {
		return certificateProfileSession;
	}

	public EndEntityManagementSessionRemote getEndEntityManagementSession() {
		return endEntityManagementSession;
	}

	public static class Builder {

		private String testUsername;
		private String testCertProfileName;
		private String testEeProfileName;
		private AuthenticationToken internalAdminToken;
		private X509CA x509TestCa;
		private EndEntityProfileSessionRemote endEntityProfileSessionRemote;
		private CertificateProfileSessionRemote certificateProfileSession;
		private EndEntityManagementSessionRemote endEntityManagementSession;

		public Builder withTestUsername(String testUsername) {
			this.testUsername = testUsername;
			return this;
		}

		public Builder withTestCertProfileName(String testCertProfileName) {
			this.testCertProfileName = testCertProfileName;
			return this;
		}

		public Builder withTestEeProfileName(String testEeProfileName) {
			this.testEeProfileName = testEeProfileName;
			return this;
		}

		public Builder withInternalAdminToken(AuthenticationToken internalAdminToken) {
			this.internalAdminToken = internalAdminToken;
			return this;
		}

		public Builder withX509TestCa(X509CA x509TestCa) {
			this.x509TestCa = x509TestCa;
			return this;
		}

		public Builder withEndEntityProfileSessionRemote(EndEntityProfileSessionRemote endEntityProfileSessionRemote) {
			this.endEntityProfileSessionRemote = endEntityProfileSessionRemote;
			return this;
		}

		public Builder withCertificateProfileSession(CertificateProfileSessionRemote certificateProfileSession) {
			this.certificateProfileSession = certificateProfileSession;
			return this;
		}

		public Builder withEndEntityManagementSession(EndEntityManagementSessionRemote endEntityManagementSession) {
			this.endEntityManagementSession = endEntityManagementSession;
			return this;
		}

		public TestEndEntityParamHolder build() {
			return new TestEndEntityParamHolder(this);
		}

	}

}
