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

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.unid.UnidFnrHandler;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Tests the unid-fnr plugin. Read the assert printout {@link #test01()} to understand how to set things up for the test.
 * 
 * @author primelars
 * @version $Id$
 */
public class CmpRAUnidTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CmpRAUnidTest.class);

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
    private static final String SUBJECT_DN = "C=SE,SN=" + SUBJECT_SN + ",CN=unid-frn";

    private String issuerDN;
    private KeyPair keys;

    private int caid;
    private final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    private X509Certificate cacert;

    private final CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private final CaSessionRemote caSession = InterfaceCache.getCaSession();
    private final CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();
    private final ConfigurationSessionRemote configurationSession = InterfaceCache.getConfigurationSession();
    private final EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Try to use AdminCA1 if it exists
        final CAInfo adminca1 = this.caSession.getCAInfo(this.admin, "AdminCA1");
        if (adminca1 == null) {
            final Collection<Integer> caids = this.caSession.getAvailableCAs(this.admin);
            final Iterator<Integer> iter = caids.iterator();
            int tmp = 0;
            while (iter.hasNext()) {
                tmp = iter.next().intValue();
                if (tmp != 0) {
                    break;
                }
            }
            this.caid = tmp;
        } else {
            this.caid = adminca1.getCAId();
        }
        if (this.caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        final CAInfo cainfo = this.caSession.getCAInfo(this.admin, this.caid);
        final Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            final Iterator<Certificate> certiter = certs.iterator();
            final Certificate cert = certiter.next();
            final String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                this.cacert = (X509Certificate) CertTools.getCertfromByteArray(cert.getEncoded());
            } else {
                this.cacert = null;
            }
        } else {
            this.cacert = null;
            log.error("NO CACERT for caid " + this.caid);
        }
        this.issuerDN = this.cacert.getIssuerDN().getName();
        // Configure CMP for this test
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, PBEPASSWORD);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "KeyId");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "KeyId");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, cainfo.getName());
        updatePropertyOnServer(CmpConfiguration.CONFIG_CERTREQHANDLER_CLASS, UnidFnrHandler.class.getName());
        // Configure a Certificate profile (CmpRA) using ENDUSER as template
        if (this.certificateProfileSession.getCertificateProfile(CPNAME) == null) {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            try { // TODO: Fix this better
                this.certificateProfileSession.addCertificateProfile(this.admin, CPNAME, cp);
            } catch (CertificateProfileExistsException e) {
                log.error("Certificate profile exists: ", e);
            }
        }
        final int cpId = this.certificateProfileSession.getCertificateProfileId(CPNAME);
        if (this.endEntityProfileSession.getEndEntityProfile(this.admin, EEPNAME) == null) {
            final EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
            try {
                this.endEntityProfileSession.addEndEntityProfile(this.admin, EEPNAME, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }
        }
        this.keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        this.endEntityProfileSession.removeEndEntityProfile(this.admin, EEPNAME);
        this.certificateProfileSession.removeCertificateProfile(this.admin, CPNAME);
        assertTrue("Unable to clean up properly.", this.configurationSession.restoreConfiguration());
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Override
    protected void checkDN(String sExpected, X509Name actual) {
        final X509Name expected = new X509Name(sExpected);
        final Vector<DERObjectIdentifier> expectedOIDs = expected.getOIDs();
        final Vector<String> expectedValues = expected.getValues();
        final Vector<DERObjectIdentifier> actualOIDs = actual.getOIDs();
        final Vector<String> actualValues = actual.getValues();
        assertEquals("Not the expected number of elements in the created certificate.", expectedOIDs.size(), actualOIDs.size());
        for (int i = 0; i < expectedOIDs.size(); i++) {
            final DERObjectIdentifier oid = expectedOIDs.get(i);
            final int j = actualOIDs.indexOf(oid);
            if (!oid.equals(X509Name.SN)) {
                log.debug("Check that " + oid.getId() + " is OK. Expected '" + expectedValues.get(i) + "'. Actual '" + actualValues.get(j) + "'.");
                assertEquals("Not expected " + oid, expectedValues.get(i), actualValues.get(j));
                continue;
            }
            log.debug("Special handling of the SN " + oid.getId() + ". Input '" + expectedValues.get(i) + "'. Transformed '" + actualValues.get(j)
                    + "'.");
            final String expectedSNPrefix = UNIDPREFIX + LRA;
            final String actualSNPrefix = actualValues.get(j).substring(0, expectedSNPrefix.length());
            assertEquals("New serial number prefix not as expected.", expectedSNPrefix, actualSNPrefix);
            final String actualSNRandom = actualValues.get(j).substring(expectedSNPrefix.length());
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
            pw.println("These properties must the also be defined for the jboss data source. The name of the DS must be set in cmp.properties. Not that the datasource must be a 'no-tx-datasource', like OcspDS.");
            pw.println("You also have to set the path to the 'mysql.jar' as the 'mysql.lib' system property for the test.");
            pw.println("Example how to the test with this property:");
            pw.println("ant -Dmysql.lib=/usr/share/java/mysql.jar test:run");
            log.error(sw, e);
            assertTrue(sw.toString(), false);
            return;
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
            final PKIMessage one = genCertReq(this.issuerDN, SUBJECT_DN, this.keys, this.cacert, nonce, transid, true, null, null, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, CPNAME, 567);
            assertNotNull(req);

            reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, this.issuerDN, SUBJECT_DN, this.cacert, nonce, transid, false, PBEPASSWORD);
            final X509Certificate cert = checkCmpCertRepMessage(SUBJECT_DN, this.cacert, resp, reqId);
            unid = (String) new X509Principal(cert.getSubjectX500Principal().getEncoded()).getValues(X509Name.SN).get(0);
            log.debug("Unid: " + unid);
        }
        {
            final PreparedStatement ps = dbConn.prepareStatement("select fnr from UnidFnrMapping where unid=?");
            ps.setString(1, unid);
            final ResultSet result = ps.executeQuery();
            assertTrue("Unid '" + unid + "' not found in DB.", result.next());
            final String fnr = result.getString(1);
            log.debug("FNR read from DB: " + fnr);
            assertEquals("Right FNR not found in DB.", FNR, fnr);
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage confirm = genCertConfirm(SUBJECT_DN, this.cacert, nonce, transid, hash, reqId);
            assertNotNull(confirm);
            final PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req1);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, this.issuerDN, SUBJECT_DN, this.cacert, nonce, transid, false, PBEPASSWORD);
            checkCmpPKIConfirmMessage(SUBJECT_DN, this.cacert, resp);
        }
    }

}
