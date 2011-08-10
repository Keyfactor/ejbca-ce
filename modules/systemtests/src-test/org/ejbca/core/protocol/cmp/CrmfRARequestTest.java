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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.util.InterfaceCache;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * @author tomas
 * @version $Id$
 */
public class CrmfRARequestTest extends CmpTestCase {

    final private static Logger log = Logger.getLogger(CrmfRARequestTest.class);

    final private static String PBEPASSWORD = "password";

    final private String issuerDN;

    final private int caid;
    final private AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    final private X509Certificate cacert;

    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CAAdminSessionRemote caAdminSessionRemote = InterfaceCache.getCAAdminSession();
    private ConfigurationSessionRemote configurationSession = InterfaceCache.getConfigurationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private EndEntityProfileSession eeProfileSession = InterfaceCache.getEndEntityProfileSession();
    private CertificateProfileSession certProfileSession = InterfaceCache.getCertificateProfileSession();

    public CrmfRARequestTest(String arg0) throws CertificateEncodingException, CertificateException, AuthorizationDeniedException, CADoesntExistsException {
        super(arg0);
        // Configure CMP for this test, we allow custom certificate serial numbers
    	CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	//profile.setAllowCertSerialNumberOverride(true);
    	try {
    		certProfileSession.addCertificateProfile(admin, "CMPTESTPROFILE", profile);
		} catch (CertificateProfileExistsException e) {
			log.error("Could not create certificate profile.", e);
		}
        int cpId = certProfileSession.getCertificateProfileId("CMPTESTPROFILE");
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES,0, "" + cpId);
        eep.addField(DnComponents.COMMONNAME);
        eep.addField(DnComponents.ORGANIZATION);
        eep.addField(DnComponents.COUNTRY);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false);	// Don't use field from "email" data
        try {
        	eeProfileSession.addEndEntityProfile(admin, "CMPTESTPROFILE", eep);
		} catch (EndEntityProfileExistsException e) {
			log.error("Could not create end entity profile.", e);
		}
        // Configure CMP for this test
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, PBEPASSWORD);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "CMPTESTPROFILE");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");

        CryptoProviderTools.installBCProvider();
        // Try to use AdminCA1 if it exists
        final CAInfo adminca1;

        adminca1 = caSession.getCAInfo(admin, "AdminCA1");

        if (adminca1 == null) {
            final Collection<Integer> caids;

            caids = caSession.getAvailableCAs(admin);

            final Iterator<Integer> iter = caids.iterator();
            int tmp = 0;
            while (iter.hasNext()) {
                tmp = iter.next().intValue();
            }
            caid = tmp;
        } else {
            caid = adminca1.getCAId();
        }
        if (caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        final CAInfo cainfo;

        cainfo = caSession.getCAInfo(admin, caid);

        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            Certificate cert = certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                try {
                    cacert = (X509Certificate) CertTools.getCertfromByteArray(cert.getEncoded());
                } catch (Exception e) {
                    throw new Error(e);
                }
            } else {
                cacert = null;
            }
        } else {
            log.error("NO CACERT for caid " + caid);
            cacert = null;
        }
        issuerDN = cacert != null ? cacert.getIssuerDN().getName() : "CN=AdminCA1,O=EJBCA Sample,C=SE";
    }

    /**
     * @param userDN
     *            for new certificate.
     * @param keys
     *            key of the new certificate.
     * @param sFailMessage
     *            if !=null then EJBCA is expected to fail. The failure response
     *            message string is checked against this parameter.
     * @throws Exception
     */
    private void crmfHttpUserTest(String userDN, KeyPair keys, String sFailMessage, BigInteger customCertSerno) throws Exception {

        // Create a new good user

        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, customCertSerno);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, sFailMessage == null, null);
            if (sFailMessage == null) {
                X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
                // verify if custom cert serial number was used
                if (customCertSerno != null) {
                	assertTrue(cert.getSerialNumber().toString(16)+" is not same as expected "+customCertSerno.toString(16), cert.getSerialNumber().equals(customCertSerno));
                }
            } else {
                checkCmpFailMessage(resp, sFailMessage, CmpPKIBodyConstants.ERRORMESSAGE, reqId, FailInfo.BAD_REQUEST.hashCode());
            }
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage con = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
            assertNotNull(con);
            PKIMessage confirm = protectPKIMessage(con, false, PBEPASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(confirm);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
            checkCmpPKIConfirmMessage(userDN, cacert, resp);
        }
    }

    public void test01CrmfHttpOkUser() throws Exception {
        final CAInfo caInfo = caSession.getCAInfo(admin, "AdminCA1");
        // make sure same keys for different users is prevented
        caInfo.setDoEnforceUniquePublicKeys(true);
        // make sure same DN for different users is prevented
        caInfo.setDoEnforceUniqueDistinguishedName(true);
        caAdminSessionRemote.editCA(admin, caInfo);

        final KeyPair key1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key3 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key4 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final String userName1 = "cmptest1";
        final String userName2 = "cmptest2";
        final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
        final String userDN2 = "C=SE,O=PrimeKey,CN=" + userName2;
        String hostname=null;
        try {
        	// check that several certificates could be created for one user and one key.
        	crmfHttpUserTest(userDN1, key1, null, null);
        	crmfHttpUserTest(userDN2, key2, null, null);
        	// check that the request fails when asking for certificate for another
        	// user with same key.
        	crmfHttpUserTest(userDN2, key1, InternalEjbcaResources.getInstance().getLocalizedMessage("signsession.key_exists_for_another_user", "'" + userName2 + "'",
        			"'" + userName1 + "'"), null);
        	crmfHttpUserTest(userDN1, key2, InternalEjbcaResources.getInstance().getLocalizedMessage("signsession.key_exists_for_another_user", "'" + userName1 + "'",
        			"'" + userName2 + "'"), null);
        	// check that you can not issue a certificate with same DN as another
        	// user.
        	crmfHttpUserTest("CN=AdminCA1,O=EJBCA Sample,C=SE", key3, InternalEjbcaResources.getInstance().getLocalizedMessage(
        			"signsession.subjectdn_exists_for_another_user", "'AdminCA1'", "'SYSTEMCA'"), null);

        	hostname = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME, "localhost");

        	crmfHttpUserTest("CN=" + hostname + ",O=EJBCA Sample,C=SE", key4, InternalEjbcaResources.getInstance().getLocalizedMessage(
        			"signsession.subjectdn_exists_for_another_user", "'" + hostname + "'", "'tomcat'"), null);

        } finally {
        	try {
        		userAdminSession.deleteUser(admin, userName1);
        	} catch (NotFoundException e) {}
        	try {
        		userAdminSession.deleteUser(admin, userName2);        	
        	} catch (NotFoundException e) {}
        	try {
        		userAdminSession.deleteUser(admin, "AdminCA1");
        	} catch (NotFoundException e) {}
        	try {
        		userAdminSession.deleteUser(admin, hostname);
        	} catch (NotFoundException e) {}
        }
    }

    public void testZZZCleanUp() throws Exception {
    	log.trace(">testZZZCleanUp");
        assertTrue("Unable to restore server configuration.", configurationSession.restoreConfiguration());
        // Remove test profiles
        certProfileSession.removeCertificateProfile(admin, "CMPTESTPROFILE");
        eeProfileSession.removeEndEntityProfile(admin, "CMPTESTPROFILE");
    	log.trace("<testZZZCleanUp");
    }
}
