/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.resource.util;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import java.util.Arrays;

public class CertificateRestResourceSystemTestUtil {

	/**
	 * Creates a test End Entity
	 */
	public EndEntityInformation createTestEndEntity(TestEndEntityParamHolder paramHolder) throws Exception {
		X509CA x509TestCa = paramHolder.getX509TestCa();
		final int certificateProfileId = createCertificateProfile(paramHolder);
		final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
		endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
		endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
		endEntityProfile.setAvailableCAs(Arrays.asList(x509TestCa.getCAId()));
		endEntityProfile.setDefaultCA(x509TestCa.getCAId());
		final int endEntityProfileId = paramHolder.getEndEntityProfileSessionRemote().addEndEntityProfile(
				paramHolder.getInternalAdminToken(), paramHolder.getTestEeProfileName(), endEntityProfile);
		String testUsername = paramHolder.getTestUsername();

		final EndEntityInformation userdata = new EndEntityInformation(testUsername,
				"CN=" + testUsername,
				x509TestCa.getCAId(),
				null,
				null,
				new EndEntityType(EndEntityTypes.ENDUSER),
				EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
				certificateProfileId,
				SecConst.TOKEN_SOFT_P12,
				new ExtendedInformation());
		userdata.setPassword("foo123");
		userdata.setStatus(EndEntityConstants.STATUS_NEW);
		userdata.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
		userdata.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");
		userdata.setEndEntityProfileId(endEntityProfileId);
		return paramHolder
				.getEndEntityManagementSession()
				.addUser(paramHolder.getInternalAdminToken(), userdata, false);
	}

	/**
	 * Creates a test certificate profile and returns its ID
	 */
	private int createCertificateProfile(TestEndEntityParamHolder paramHolder) throws Exception {
		CertificateProfileSessionRemote certificateProfileSession = paramHolder.getCertificateProfileSession();
		int certificateProfileId = certificateProfileSession.getCertificateProfileId(
				paramHolder.getTestCertProfileName());
		if (certificateProfileId == 0) {
			final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
			certificateProfile.setAvailableCAs(Arrays.asList(paramHolder.getX509TestCa().getCAId()));
			certificateProfileId = certificateProfileSession.addCertificateProfile(paramHolder.getInternalAdminToken(),
					paramHolder.getTestCertProfileName(), certificateProfile);
		}
		return certificateProfileId;
	}
}
