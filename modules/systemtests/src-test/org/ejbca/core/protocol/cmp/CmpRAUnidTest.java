/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority						  *
 *																	   *
 *  This software is free software; you can redistribute it and/or	   *
 *  modify it under the terms of the GNU Lesser General Public		   *
 *  License as published by the Free Software Foundation; either		 *
 *  version 2.1 of the License, or any later version.					*
 *																	   *
 *  See terms of license at gnu.org.									 *
 *																	   *
 *************************************************************************/

package org.ejbca.core.protocol.cmp;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.TestAssertionFailedException;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.unid.UnidFnrHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the unid-fnr plugin. Read the assert printout {@link #test01()} to understand how to set things up for the test.
 * 
 * @author primelars
 * @version $Id$
 */
public class CmpRAUnidTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CmpRAUnidTest.class);
    private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmpRAUnidTest"));

    private static final String PBEPASSWORD = "password";
    private static final String UNIDPREFIX = "1234-5678-";
    private static final String CPNAME = UNIDPREFIX + CmpRAUnidTest.class.getName();
    private static final String EEPNAME = UNIDPREFIX + CmpRAUnidTest.class.getName();

    /**
     * SUBJECT_DN of user used in this test, this contains special, escaped, characters to test that this works with CMP RA operations
     */
    private static final String FNR = "90123456789";
    private static final String LRA = "01234";
    private static final String SUBJECT_SN = FNR + '-' + LRA;
    private static final X500Name SUBJECT_DN = new X500Name("C=SE,SN=" + SUBJECT_SN + ",CN=unid-frn");

    private static final String issuerDN = "CN=TestCA";
    private final KeyPair keys;
    private final int caid;
    private final X509Certificate cacert;
    private final CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    private static final String configAlias = "CmpRAUnidTestCmpConfAlias";
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    public CmpRAUnidTest() throws Exception {
        this.keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        this.testx509ca = CaTestUtils.createTestX509CA(issuerDN, null, false, keyusage);
        this.caid = this.testx509ca.getCAId();
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
    }
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        this.caSession.addCA(this.admin, this.testx509ca);
        
        this.configurationSession.backupConfiguration();
        
        // Configure CMP for this test
        this.cmpConfiguration.addAlias(configAlias);
        this.cmpConfiguration.setRAMode(configAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(configAlias, true);
        this.cmpConfiguration.setResponseProtection(configAlias, "pbe");
        this.cmpConfiguration.setRACertProfile(configAlias, "KeyId");
        this.cmpConfiguration.setRAEEProfile(configAlias, "KeyId");
        this.cmpConfiguration.setRACAName(configAlias, this.testx509ca.getName());
        this.cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(configAlias, "-;" + PBEPASSWORD);
        this.cmpConfiguration.setCertReqHandlerClass(configAlias, UnidFnrHandler.class.getName());
        this.cmpConfiguration.setUnidDataSource(configAlias, "java:/UnidDS");
        this.globalConfigurationSession.saveConfiguration(this.admin, this.cmpConfiguration, Configuration.CMPConfigID);
        
        // Configure a Certificate profile (CmpRA) using ENDUSER as template
        if (this.certProfileSession.getCertificateProfile(CPNAME) == null) {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            try { // TODO: Fix this better
                this.certProfileSession.addCertificateProfile(this.admin, CPNAME, cp);
            } catch (CertificateProfileExistsException e) {
                log.error("Certificate profile exists: ", e);
            }
        }
        final int cpId = this.certProfileSession.getCertificateProfileId(CPNAME);
        if (this.endEntityProfileSession.getEndEntityProfile(EEPNAME) == null) {
            final EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
            try {
                this.endEntityProfileSession.addEndEntityProfile(this.admin, EEPNAME, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }
        }
        
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        this.endEntityProfileSession.removeEndEntityProfile(this.admin, EEPNAME);
        this.certProfileSession.removeCertificateProfile(this.admin, CPNAME);
        
        CryptoTokenTestUtils.removeCryptoToken(null, this.testx509ca.getCAToken().getCryptoTokenId());
        this.caSession.removeCA(this.admin, this.caid);
        
        assertTrue("Unable to clean up properly.", this.configurationSession.restoreConfiguration());
        this.cmpConfiguration.removeAlias(configAlias);
        this.globalConfigurationSession.saveConfiguration(this.admin, this.cmpConfiguration, Configuration.CMPConfigID);
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Override
    protected void checkDN(X500Name expected, X500Name actual) {
        final ASN1ObjectIdentifier[] expectedOIDs = expected.getAttributeTypes();
        final ASN1ObjectIdentifier[] actualOIDs = actual.getAttributeTypes();
        assertEquals("Not the expected number of elements in the created certificate.", expectedOIDs.length, actualOIDs.length);
        String expectedValue, actualValue;
        for (int i = 0; i < expectedOIDs.length; i++) {
            final ASN1ObjectIdentifier oid = expectedOIDs[i];
            expectedValue = expected.getRDNs(oid)[0].getFirst().getValue().toString();
            actualValue = actual.getRDNs(oid)[0].getFirst().getValue().toString();
            if (!oid.equals(BCStyle.SN)) {
                log.debug("Check that " + oid.getId() + " is OK. Expected '" + expectedValue + "'. Actual '" + actualValue + "'.");
                assertEquals("Not expected " + oid, expectedValue, actualValue);
                continue;
            }
            log.debug("Special handling of the SN " + oid.getId() + ". Input '" + expectedValue + "'. Transformed '" + actualValue
                    + "'.");
            final String expectedSNPrefix = UNIDPREFIX + LRA;
            final String actualSNPrefix = actualValue.substring(0, expectedSNPrefix.length());
            assertEquals("New serial number prefix not as expected.", expectedSNPrefix, actualSNPrefix);
            final String actualSNRandom = actualValue.substring(expectedSNPrefix.length());
            assertTrue("Random in serial number not OK: " + actualSNRandom, Pattern.compile("^\\w{6}$").matcher(actualSNRandom).matches());
        }
    }

    @Test
    public void test01() throws Exception {
        final Connection connection;
        final String host = "localhost";
        final String user = "uniduser";
        final String pass = "unidpass";
        final String name = "unid";
        try {
            connection = DriverManager.getConnection("jdbc:mysql://" + host + ":3306/" + name, user, pass);
        } catch (SQLException e) {
            final StringWriter sw = new StringWriter();
            final PrintWriter pw = new PrintWriter(sw);
            pw.println();
            pw.println("You have not set up a unid-fnr DB properly to run the test.");
            pw.println("If you don't bother about it (don't if you don't know what it is) please just ignore this error.");
            pw.println("But if you want to run the test please make sure that the mysql unid-fnr DB is set up.");
            pw.println("Then execute next line at the mysql prompt:");
            pw.println("mysql> grant all on " + name + ".* to " + user + "@'" + host + "' identified by '" + pass + "';");
            pw.println("And then create the DB:");
            pw.println("$ mysqladmin -u" + host + " -u" + user + " -p" + pass + " create " + name + ";.");
            pw.println("These properties must the also be defined for the jboss data source. The name of the DS must be set in cmp.properties. Note that the datasource must be a 'no-tx-datasource', like OcspDS.");
            pw.println("You also have to set the path to the 'mysql.jar' as the 'mysql.lib' system property for the test.");
            pw.println("Example how to the test with this property:");
            pw.println("ant -Dmysql.lib=/usr/share/java/mysql.jar test:run");
            log.error(sw, e);
            throw new TestAssertionFailedException(sw.toString());
        }
        try {
            doTest(connection);
        } finally {
            connection.close();
        }
    }

    private void doTest(Connection dbConn) throws Exception {

        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        final String unid;
        {
            // In this test SUBJECT_DN contains special, escaped characters to verify
            // that that works with CMP RA as well
            final PKIMessage one = genCertReq(CmpRAUnidTest.issuerDN, SUBJECT_DN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, CPNAME, 567);
            assertNotNull(req);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            
            ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
            try {
                PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
                PKIBody body = respObject.getBody();
                if (body.getContent() instanceof ErrorMsgContent) {
                    ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                    String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                    log.error(errMsg);
                    fail("CMP ErrorMsg received: " + errMsg);
                    unid = null;
                } else {
                    checkCmpResponseGeneral(resp, CmpRAUnidTest.issuerDN, SUBJECT_DN, this.cacert, nonce, transid, false, PBEPASSWORD,
                            PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                    final X509Certificate cert = checkCmpCertRepMessage(SUBJECT_DN, this.cacert, resp, reqId);
                    final X500Name name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
                    unid = IETFUtils.valueToString(name.getRDNs(BCStyle.SN)[0].getFirst().getValue());
                    log.debug("Unid received in certificate response: " + unid);
                }
            } finally {
                inputStream.close();
            }
        }
        {
            final PreparedStatement ps = dbConn.prepareStatement("select fnr from UnidFnrMapping where unid=?");
            ps.setString(1, unid);
            final ResultSet result = ps.executeQuery();
            assertTrue("Unid '" + unid + "' not found in DB.", result.next());
            final String fnr = result.getString(1);
            result.close();
            ps.close();
            log.debug("FNR read from DB: " + fnr);
            assertEquals("Right FNR not found in DB.", FNR, fnr);
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage confirm = genCertConfirm(SUBJECT_DN, this.cacert, nonce, transid, hash, reqId);
            assertNotNull(confirm);
            final PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, CPNAME, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req1);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, CmpRAUnidTest.issuerDN, SUBJECT_DN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(SUBJECT_DN, this.cacert, resp);
        }
    }

}
