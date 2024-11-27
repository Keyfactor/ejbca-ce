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
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.db.DatabaseContentRule;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * System tests for handling CRMF messages requests with custom certificate 
 * serial number.
 */
public class CrmfRARequestCustomSerialNoSystemTest extends CmpTestCase {

    final private static Logger log = Logger.getLogger(CrmfRARequestCustomSerialNoSystemTest.class);

    final private static String PBE_PASSWORD = "password";
    final private static String CMP_ALIAS = "CmpCustomSerialNoTestAlias";

    private String issuerDN;
    private CAInfo caInfo;
    private X509Certificate cacert;
    private CmpConfiguration cmpConfiguration;

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @ClassRule
    public static DatabaseContentRule databaseContentRule = new DatabaseContentRule();

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        this.caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        this.globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

        // Try to use ManagementCA if it exists
        final CAInfo managementCA = this.caSession.getCAInfo(ADMIN, "ManagementCA");
        if (managementCA == null) {
            var list = this.caSession.getAuthorizedCaInfos(ADMIN);
            assertFalse("No active CA! Must have at least one active CA to run tests!", list.isEmpty());
            this.caInfo = list.get(list.size() - 1);
        } else {
            this.caInfo = managementCA;
        }

        Collection<Certificate> certs = caInfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> caIter = certs.iterator();
            Certificate cert = caIter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, caInfo.getSubjectDN())) {
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
            log.error("NO CACERT for caid " + this.caInfo.getCAId());
            this.cacert = null;
        }
        this.issuerDN = this.cacert != null &&
                        this.cacert.getIssuerX500Principal() != null &&
                        StringUtils.isEmpty(this.cacert.getIssuerX500Principal().getName()) ?
                this.cacert.getIssuerX500Principal().getName() :
                "CN=ManagementCA,O=EJBCA Sample,C=SE";

        // Configure CMP for this test
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        this.cmpConfiguration.addAlias(CMP_ALIAS);
        this.cmpConfiguration.setRAMode(CMP_ALIAS, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(CMP_ALIAS, true);
        this.cmpConfiguration.setResponseProtection(CMP_ALIAS, "signature");
        this.cmpConfiguration.setRAEEProfile(CMP_ALIAS, String.valueOf(eepDnOverrideId));
        this.cmpConfiguration.setRACertProfile(CMP_ALIAS, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRACAName(CMP_ALIAS, "ManagementCA");
        this.cmpConfiguration.setRANameGenScheme(CMP_ALIAS, "DN");
        this.cmpConfiguration.setRANameGenParams(CMP_ALIAS, "CN");
        this.cmpConfiguration.setAllowRACustomSerno(CMP_ALIAS, false);
        this.cmpConfiguration.setAuthenticationModule(CMP_ALIAS, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(CMP_ALIAS, "-;" + PBE_PASSWORD);
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
            final PKIMessage req = protectPKIMessage(one, false, PBE_PASSWORD, 567);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, this.issuerDN, userDN, this.cacert, nonce, transid, sFailMessage == null, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            if (sFailMessage == null) {
            	ret = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, userDN, this.cacert, resp, reqId);
                // verify if custom cert serial number was used
                if (customCertSerno != null) {
                	assertTrue(ret.getSerialNumber().toString(16)+" is not same as expected "+customCertSerno.toString(16), ret.getSerialNumber().equals(customCertSerno));
                }
            } else {
                checkCmpFailMessage(resp, sFailMessage, CmpPKIBodyConstants.ERRORMESSAGE, reqId, PKIFailureInfo.badRequest);
            }
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage con = genCertConfirm(userDN, this.cacert, nonce, transid, hash, reqId, null);
            assertNotNull(con);
            PKIMessage confirm = protectPKIMessage(con, false, PBE_PASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
            out.writeObject(confirm);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, this.issuerDN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
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
    		long serialNumber = RandomUtils.nextLong();
    		BigInteger bigInteger = BigInteger.valueOf(serialNumber);
            // First it should fail because the CMP RA does not even look for, or parse, requested custom certificate serial numbers
            // Actually it does not fail here, but returns good answer
    		X509Certificate cert = crmfHttpUserTest(userDN1, key1, null, null);
            assertNotNull("Failed to create cert", cert);
    		assertFalse("SerialNumbers should not be equal when custom serial numbers are not allowed.", bigInteger.equals(cert.getSerialNumber()));
    		
    		
            // Second it should fail when the certificate profile does not allow serial number override
            // crmfHttpUserTest checks the returned serno if bint parameter is not null
    		this.cmpConfiguration.setAllowRACustomSerno(CMP_ALIAS, true);
    		this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    		crmfHttpUserTest(userDN1, key1, "Used certificate profile ('"+this.cpDnOverrideId+"') is not allowing certificate serial number override.", bigInteger);
    		
    		
    		// Third it should succeed and we should get our custom requested serialnumber
    		this.cmpConfiguration.setAllowRACustomSerno(CMP_ALIAS, true);
    		this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    		CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);
    		cp.setAllowCertSerialNumberOverride(true);
    		// Now when the profile allows serial number override it should work
    		this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
    		crmfHttpUserTest(userDN1, key1, null, bigInteger);
    	} finally {
    		try {
    			this.endEntityManagementSession.deleteUser(ADMIN, userName1);
    		} catch (NoSuchEndEntityException e) {/* do nothing */}
    	}
    }

    @Override
    @After
    public void tearDown() throws Exception {
    	super.tearDown();
        this.cmpConfiguration.removeAlias(CMP_ALIAS);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
}
