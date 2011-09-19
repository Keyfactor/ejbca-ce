/************************************************************************
 *																		*
 *  EJBCA: The OpenSource Certificate Authority							*
 *																		*
 *  This software is free software; you can redistribute it and/or		*
 *  modify it under the terms of the GNU Lesser General Public			*
 *  License as published by the Free Software Foundation; either		*
 *  version 2.1 of the License, or any later version.					*
 *																		*
 *  See terms of license at gnu.org.									*
 *																		*
 ***********************************************************************/
package org.ejbca.core.protocol.ws;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test of certificate extensions with values from WS.
 * 
 * @author Lars Silvén
 * @version $Id$
 */
public class CertificateExtensionTest extends CommonEjbcaWS {

	private static final Logger log = Logger.getLogger(CertificateExtensionTest.class);
	private final String wsadminRoleName = "CertificateExtensionTest";	
	private static final String CERTIFICATE_PROFILE = "certExtension";
	private static final String TEST_USER = "certExtension";
	private static final String END_ENTITY_PROFILE = "endEntityProfile";

	@BeforeClass
	public static void setupAccessRights() {
		adminBeforeClass();
	}

	@Before
	public void setUpAdmin() throws Exception {
		adminSetUpAdmin();
	}

	@Override
	@After
	public void tearDown() throws Exception {
		super.tearDown();
	}

	@Test
	public void test00setupAccessRights() throws Exception {
		super.setupAccessRights(this.wsadminRoleName);
	}

	@Test
	public void test1() throws Exception {
		if (this.certificateProfileSession.getCertificateProfileId(CERTIFICATE_PROFILE) != 0) {
			this.certificateProfileSession.removeCertificateProfile(intAdmin, CERTIFICATE_PROFILE);
		}
		final int certProfID; {
			final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
			final List<Integer> usedCertificateExtensions = new LinkedList<Integer>();
			usedCertificateExtensions.add(new Integer(1));
			profile.setUsedCertificateExtensions(usedCertificateExtensions);
			this.certificateProfileSession.addCertificateProfile(intAdmin, CERTIFICATE_PROFILE, profile);
			certProfID = this.certificateProfileSession.getCertificateProfileId(CERTIFICATE_PROFILE);
		}
		if ( this.endEntityProfileSession.getEndEntityProfile(intAdmin, END_ENTITY_PROFILE)!=null ) {
			this.endEntityProfileSession.removeEndEntityProfile(intAdmin, END_ENTITY_PROFILE);
		}
		{
			final EndEntityProfile profile = new EndEntityProfile(true);
			profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certProfID));
			this.endEntityProfileSession.addEndEntityProfile(intAdmin, END_ENTITY_PROFILE, profile);
		}

		final UserDataVOWS userData = new UserDataVOWS(TEST_USER, PASSWORD, true, "C=SE, CN=cert extension test",
				getAdminCAName(), null, "foo@anatom.se", UserDataVOWS.STATUS_NEW,
				UserDataVOWS.TOKEN_TYPE_USERGENERATED, END_ENTITY_PROFILE, CERTIFICATE_PROFILE, null);
		final String sOID = "1.2.3.4";
		final byte input[] = new byte[400];
		new Random().nextBytes(input);
		{
			final List<ExtendedInformationWS> lei = new LinkedList<ExtendedInformationWS>();
			final ExtendedInformationWS ei = new ExtendedInformationWS();
			ei.setName(sOID);
			ei.setValue(new String(Hex.encode(input)));
			lei.add(ei);
			userData.setExtendedInformation(lei);
		}
		this.ejbcaraws.editUser(userData);

		final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
		final PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"), keys.getPublic(),
				new DERSet(), keys.getPrivate());

		final CertificateResponse certenv = this.ejbcaraws.pkcs10Request(TEST_USER, PASSWORD, new String(Base64.encode(pkcs10.getEncoded())), null,
				CertificateHelper.RESPONSETYPE_CERTIFICATE);

		assertNotNull(certenv);
		assertTrue(certenv.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
		final X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());
		final byte extension[] = cert.getExtensionValue(sOID);
		assertNotNull(getNoCertExtensionProperties(sOID), extension);
		final ASN1Object asn1o = ASN1Object.fromByteArray(extension);
		assertNotNull(asn1o);
		log.info("Extension: "+asn1o);
		assertTrue(asn1o instanceof ASN1OctetString);
		assertArrayEquals(input, ((ASN1OctetString)asn1o).getOctets());
	}
	private String getNoCertExtensionProperties(String sOID) {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw);
		pw.println("No '"+sOID+"' extension in generated certificate.");
		pw.println("The reason might be that '"+sOID+"' is not defined in the file src/java/certextensions.properties .");
		pw.println("The files should look something like this:");
		pw.println();
		pw.println("id1.oid = "+sOID);
		pw.println("id1.classpath=org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension");
		pw.println("id1.displayname=TESTEXTENSION");
		pw.println("id1.used=true");
		pw.println("id1.translatable=false");
		pw.println("id1.critical=false");
		pw.println("id1.property.dynamic=true");
		pw.println("id1.property.encoding=RAW");
		pw.flush();
		return sw.toString();
	}
	
	public void test99cleanUpAdmins() {
		try {
			this.certificateProfileSession.removeCertificateProfile(intAdmin, CERTIFICATE_PROFILE);
		} catch (Throwable e) {
			// do nothing
		}
		try {
			this.endEntityProfileSession.removeEndEntityProfile(intAdmin, END_ENTITY_PROFILE);
		} catch (Throwable e) {
			// do nothing
		}
		try {
			this.userAdminSession.revokeAndDeleteUser(intAdmin, TEST_USER, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
		} catch (Throwable e) {
			// do nothing
		}
		try {
			super.cleanUpAdmins(this.wsadminRoleName);
		} catch (Throwable e) {
			// do nothing
		}
	}
	@Override
	public String getRoleName() {
		return this.wsadminRoleName+"Mgmt";
	}
}
