/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayOutputStream;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/** These tests test RA functionality with the CMP protocol, i.e. a "trusted" RA sends CMP messages authenticated using PBE (password based encryption)
 * and these requests are handled by EJBCA without further authentication, end entities are created automatically in EJBCA.
 * 
 * You need a CMP TCP listener configured on port 5587 to run this test.
 * (cmp.tcp.enabled=true, cmp.tcp.portno=5587)
 * 
 * 'ant clean; ant bootstrap' to deploy configuration changes.
 * 
 * @author tomas
 * @version $Id$
 */
public class CrmfRAPbeTcpRequestTest extends CmpTestCase {
	
    private static final Logger log = Logger.getLogger(CrmfRAPbeTcpRequestTest.class);

    private static final String PBEPASSWORD        = "password";
    private static final String CPNAME             = CrmfRAPbeTcpRequestTest.class.getName();
    private static final String EEPNAME            = CrmfRAPbeTcpRequestTest.class.getName();

    /** userDN of user used in this test, this contains special, escaped, characters to test that this works with CMP RA operations */
    private static String userDN = "C=SE,O=PrimeKey'foo'&bar\\,ha\\<ff\\\"aa,CN=cmptest";
    
    private static String issuerDN                 = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;  

    private static int caid = 0;
    private static final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
    private static X509Certificate cacert = null;

    /** This is the same constructor as in CrmtRAPbeRequestTest, but it's hard to refactor not to duplicate this code.
     */
	public CrmfRAPbeTcpRequestTest(String arg0) throws RemoteException, CertificateException {
		super(arg0);
		CryptoProviderTools.installBCProvider();
        // Try to use AdminCA1 if it exists
        CAInfo adminca1 = TestTools.getCAAdminSession().getCAInfo(admin, "AdminCA1");
        if (adminca1 == null) {
            Collection caids = TestTools.getCAAdminSession().getAvailableCAs(admin);
            Iterator iter = caids.iterator();
            while (iter.hasNext()) {
            	caid = ((Integer) iter.next()).intValue();
            }        	
        } else {
        	caid = adminca1.getCAId();
        }
        if (caid == 0) {
        	assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }        	
        CAInfo cainfo = TestTools.getCAAdminSession().getCAInfo(admin, caid);
        Collection certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            X509Certificate cert = (X509Certificate) certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                cacert = (X509Certificate)CertTools.getCertfromByteArray(cert.getEncoded());            	
            }
        } else {
            log.error("NO CACERT for caid " + caid);
        }
        issuerDN = cacert.getIssuerDN().getName();
        // Configure CMP for this test
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, "password");
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, CPNAME);
        TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, EEPNAME);
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and check "Allow validity override".
        if (TestTools.getCertificateStoreSession().getCertificateProfile(admin, CPNAME) == null) {
            CertificateProfile cp = new EndUserCertificateProfile();
            cp.setAllowValidityOverride(true);
            try {	// TODO: Fix this better
				TestTools.getCertificateStoreSession().addCertificateProfile(admin, CPNAME, cp);
			} catch (CertificateProfileExistsException e) {
				e.printStackTrace();
			}
        }
        int cpId = TestTools.getCertificateStoreSession().getCertificateProfileId(admin, CPNAME);
        if (TestTools.getRaAdminSession().getEndEntityProfile(admin, EEPNAME) == null) {
            // Configure an EndEntity profile (CmpRA) with allow CN, O, C in DN and rfc822Name (uncheck 'Use entity e-mail field' and check 'Modifyable'), MS UPN in altNames in the end entity profile.
            EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, "" + cpId);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES,0, "" + cpId);
            eep.setModifyable(DnComponents.RFC822NAME, 0, true);
            eep.setUse(DnComponents.RFC822NAME, 0, false);	// Don't use field from "email" data
            try {
    			TestTools.getRaAdminSession().addEndEntityProfile(admin, EEPNAME, eep);
    		} catch (EndEntityProfileExistsException e) {
    			log.error("Could not create end entity profile.", e);
    		}
        }
	}
	
	public void setUp() throws Exception {
		super.setUp();
		if (keys == null) {
			keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		}
	}
	
	public void tearDown() throws Exception {
		super.tearDown();
	}

	public void test02CrmfTcpOkUser() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
		assertNotNull(req);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DEROutputStream out = new DEROutputStream(bao);
		out.writeObject(req);
		byte[] ba = bao.toByteArray();
		// Send request and receive response
		byte[] resp = sendCmpTcp(ba, 5);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
		assertNotNull(cert);
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
		assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(req1);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpTcp(ba, 5);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(userDN, cacert, resp);
		
		// Now revoke the bastard using the CMPv2 CRL entry extension!
		PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), cacert, nonce, transid, true);
        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
		assertNotNull(revReq);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(revReq);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpTcp(ba, 5);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, true);
		int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
		assertEquals(reason, RevokedCertInfo.REVOKATION_REASON_CESSATIONOFOPERATION);

	}

	public void testZZZCleanUp() throws Exception {
		try {
			TestTools.getUserAdminSession().deleteUser(admin, "cmptest");
		} catch (NotFoundException e) {
			// A test probably failed before creating the entity
		}
		TestTools.getRaAdminSession().removeEndEntityProfile(admin, EEPNAME);
		TestTools.getCertificateStoreSession().removeCertificateProfile(admin, CPNAME);
		TestTools.getConfigurationSession().restoreConfiguration();
	}
	

}
