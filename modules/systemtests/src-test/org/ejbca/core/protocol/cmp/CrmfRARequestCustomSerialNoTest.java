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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.RandomUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.ra.NotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author tomas
 * @version $Id$
 */
public class CrmfRARequestCustomSerialNoTest extends CmpTestCase {

    final private static Logger log = Logger.getLogger(CrmfRARequestCustomSerialNoTest.class);

    final private static String PBEPASSWORD = "password";
    final private String issuerDN;
    final private int caid;
    final private X509Certificate cacert;
    final private CmpConfiguration cmpConfiguration;
    final private static String cmpAlias = "CmpCustomSerialNoTestAlias";

    final private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    final private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    public CrmfRARequestCustomSerialNoTest() throws Exception {
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);

        // Try to use ManagementCA if it exists
        final CAInfo managementca;

        managementca = this.caSession.getCAInfo(ADMIN, "ManagementCA");

        if (managementca == null) {
            final Collection<Integer> caids;

            caids = this.caSession.getAuthorizedCaIds(ADMIN);

            final Iterator<Integer> iter = caids.iterator();
            int tmp = 0;
            while (iter.hasNext()) {
                tmp = iter.next().intValue();
            }
            this.caid = tmp;
        } else {
            this.caid = managementca.getCAId();
        }
        if (this.caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        final CAInfo cainfo;

        cainfo = this.caSession.getCAInfo(ADMIN, this.caid);

        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            Certificate cert = certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                try {
                    this.cacert = CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);
                } catch (Exception e) {
                    throw new Error(e);
                }
            } else {
                this.cacert = null;
            }
        } else {
            log.error("NO CACERT for caid " + this.caid);
            this.cacert = null;
        }
        this.issuerDN = this.cacert != null ? this.cacert.getIssuerDN().getName() : "CN=ManagementCA,O=EJBCA Sample,C=SE";
    }
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        // Configure CMP for this test
        this.cmpConfiguration.addAlias(cmpAlias);
        this.cmpConfiguration.setRAMode(cmpAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(cmpAlias, true);
        this.cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        this.cmpConfiguration.setRAEEProfile(cmpAlias, EEP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRACertProfile(cmpAlias, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRACAName(cmpAlias, "ManagementCA");
        this.cmpConfiguration.setRANameGenScheme(cmpAlias, "DN");
        this.cmpConfiguration.setRANameGenParams(cmpAlias, "CN");
        this.cmpConfiguration.setAllowRACustomSerno(cmpAlias, false);
        this.cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "-;" + PBEPASSWORD);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    /**
     * @param userDN
     *            for new certificate.
     * @param keys
     *            key of the new certificate.
     * @param sFailMessage
     *            if !=null then EJBCA is expected to fail. The failure response
     *            message string is checked against this parameter.
     * @return If it is a certificate request that results in a successful certificate issuance, this certificate is returned
     * @throws Exception
     */
    private X509Certificate crmfHttpUserTest(X500Name userDN, KeyPair keys, String sFailMessage, BigInteger customCertSerno) throws Exception {

        X509Certificate ret = null;
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        {
            final PKIMessage one = genCertReq(this.issuerDN, userDN, keys, this.cacert, nonce, transid, true, null, null, null, customCertSerno, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, this.issuerDN, userDN, this.cacert, nonce, transid, sFailMessage == null, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            if (sFailMessage == null) {
            	ret = checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
                // verify if custom cert serial number was used
                if (customCertSerno != null) {
                	assertTrue(ret.getSerialNumber().toString(16)+" is not same as expected "+customCertSerno.toString(16), ret.getSerialNumber().equals(customCertSerno));
                }
            } else {
                checkCmpFailMessage(resp, sFailMessage, CmpPKIBodyConstants.ERRORMESSAGE, reqId, PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);
            }
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage con = genCertConfirm(userDN, this.cacert, nonce, transid, hash, reqId);
            assertNotNull(con);
            PKIMessage confirm = protectPKIMessage(con, false, PBEPASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(confirm);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, this.issuerDN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(userDN, this.cacert, resp);
        }
        return ret;
    }

    @Test
    public void test01CustomCertificateSerialNumber() throws Exception {
    	final KeyPair key1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    	final String userName1 = "cmptest1";
    	final X500Name userDN1 = new X500Name("C=SE,O=PrimeKey,CN=" + userName1);
    	try {
    		// check that several certificates could be created for one user and one key.
    		long serno = RandomUtils.nextLong();
    		BigInteger bint = BigInteger.valueOf(serno);
            // First it should fail because the CMP RA does not even look for, or parse, requested custom certificate serial numbers
            // Actually it does not fail here, but returns good answer
    		X509Certificate cert = crmfHttpUserTest(userDN1, key1, null, null);
    		assertFalse("SerialNumbers should not be equal when custom serialnumbers are not allowed.", bint.equals(cert.getSerialNumber()));
    		
    		
            // Second it should fail when the certificate profile does not allow serial number override
            // crmfHttpUserTest checks the returned serno if bint parameter is not null
    		this.cmpConfiguration.setAllowRACustomSerno(cmpAlias, true);
    		this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    		crmfHttpUserTest(userDN1, key1, "Used certificate profile ('"+this.cpDnOverrideId+"') is not allowing certificate serial number override.", bint);
    		
    		
    		// Third it should succeed and we should get our custom requested serialnumber
    		this.cmpConfiguration.setAllowRACustomSerno(cmpAlias, true);
    		this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    		CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);
    		cp.setAllowCertSerialNumberOverride(true);
    		// Now when the profile allows serial number override it should work
    		this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
    		crmfHttpUserTest(userDN1, key1, null, bint);
    	} finally {
    		try {
    			this.endEntityManagementSession.deleteUser(ADMIN, userName1);
    		} catch (NotFoundException e) {/* do nothing */}
    	}
    }

    @Override
    @After
    public void tearDown() throws Exception {
    	super.tearDown();
        this.cmpConfiguration.removeAlias(cmpAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
}
