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
package org.cesecore.certificates.crl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Basic vanilla tests for CrlCreateSession. Contains quite some code lifted from PublishingCrlSession that doesn't belong under the CESeCore
 * package. 
 * 
 * @version $Id$
 *
 */
public class CrlCreateSessionTest {

    private static final Logger log = Logger.getLogger(CrlCreateSessionTest.class);

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CaTestSessionRemote caTestSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private final CrlCreateSessionRemote crlCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlCreateSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final String className = CrlCreateSessionTest.class.getSimpleName();
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CrlCreateSessionTest.class.getSimpleName());

    private static final byte[] TEST_AKID = new byte[] { 1, 2, 3, 4 };

    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CaTestUtils.createX509Ca(authenticationToken, className, className, "CN="+className);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        CaTestUtils.removeCA(authenticationToken, className, className);
    }

    @Test
    public void createCrl() throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        int caid = caSession.getCAInfo(authenticationToken, className).getCAId();
        CA ca = caTestSessionRemote.getCA(authenticationToken, caid);
        final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
        Collection<RevokedCertInfo> revcerts = certificateStoreSession.listRevokedCertInfo(certSubjectDN, -1);
        int fullnumber = crlStoreSession.getLastCRLNumber(certSubjectDN, false);
        int deltanumber = crlStoreSession.getLastCRLNumber(certSubjectDN, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;

        crlCreateSession.generateAndStoreCRL(authenticationToken, ca, revcerts, -1, nextCrlNumber);
        // We should now have a CRL generated
        byte[] crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), false);
        try {
            assertNotNull(crl);
            // Check that it is signed by the correct public key
            X509CRL xcrl = CertTools.getCRLfromByteArray(crl);
            PublicKey pubK = ca.getCACertificate().getPublicKey();
            xcrl.verify(pubK);
        } catch (Exception e) {
            log.error("Error: ", e);
            fail("Should not throw here");
        } finally {
            // Remove it to clean database
            internalCertificateStoreSession.removeCRL(authenticationToken, CertTools.getFingerprintAsString(crl));
        }
    }

    
    @Test
    public void testCreateNewDeltaCRL() throws Exception {
        int caid = caSession.getCAInfo(authenticationToken, className).getCAId();
        CA ca = caTestSessionRemote.getCA(authenticationToken, caid);
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();
        cainfo.setDeltaCRLPeriod(1); // Issue very often..
        caSession.editCA(authenticationToken, cainfo);
        forceCRL(authenticationToken, ca);
        forceDeltaCRL(authenticationToken, ca);
    
        // Get number of last Delta CRL
        int number = crlStoreSession.getLastCRLNumber(ca.getSubjectDN(), true);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), true);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        assertEquals(number, num.intValue());
        // Create a new CRL again to see that the number increases
        forceDeltaCRL(authenticationToken, ca);
        int number1 = crlStoreSession.getLastCRLNumber(ca.getSubjectDN(), true);
        assertEquals(number + 1, number1);
        byte[] crl1 = crlStoreSession.getLastCRL(ca.getSubjectDN(), true);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(number + 1, num1.intValue());
        // Now create a normal CRL and a deltaCRL again. CRLNUmber should now be
        // increased by two
        forceCRL(authenticationToken, ca);
        forceDeltaCRL(authenticationToken, ca);
        int number2 = crlStoreSession.getLastCRLNumber(ca.getSubjectDN(), true);
        assertEquals(number1 + 2, number2);
        byte[] crl2 = crlStoreSession.getLastCRL(ca.getSubjectDN(), true);
        X509CRL x509crl2 = CertTools.getCRLfromByteArray(crl2);
        BigInteger num2 = CrlExtensions.getCrlNumber(x509crl2);
        assertEquals(number1 + 2, num2.intValue());
    }
    
    @Test
    public void testRemoveFromCRL() throws Exception {
        int caid = caSession.getCAInfo(authenticationToken, className).getCAId();
        CA ca = caTestSessionRemote.getCA(authenticationToken, caid);
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();
        cainfo.setDeltaCRLPeriod(1); // Issue very often..
        caSession.editCA(authenticationToken, cainfo);
        
        internalCertificateStoreSession.removeCertificatesBySubject("CN=testremovefromcrl");
        try {
            // Generate a certificate in on hold state
            final EndEntityInformation userdata = new EndEntityInformation();
            userdata.setUsername("testremovefromcrl"); // not acutally created
            userdata.setPassword("foo123");
            userdata.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            userdata.setCAId(caid);
            userdata.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            userdata.setDN("CN=testremovefromcrl");
            final PublicKey pubkey = KeyTools.genKeys("1024", "RSA").getPublic();
            final RequestMessage req = new SimpleRequestMessage(pubkey, "testremovefromcrl", "foo123");
            final Certificate cert = certificateCreateSession.createCertificate(authenticationToken, userdata, req, X509ResponseMessage.class, null).getCertificate();
            certificateStoreSession.setRevokeStatus(authenticationToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            
            // Base CRL should have the revoked certificate in the revoked state
            forceCRL(authenticationToken, ca);
            X509CRLEntry crlEntry = fetchCRLEntry(cainfo, cert, false);
            assertNotNull("Revoked certificate should be on CRL", crlEntry);
            assertEquals("Wrong revocation status on Base CRL", CRLReason.CERTIFICATE_HOLD, crlEntry.getRevocationReason());
            
            // Unrevoke the certificate
            certificateStoreSession.setRevokeStatus(authenticationToken, cert, new Date(), RevokedCertInfo.NOT_REVOKED);
            
            // Delta CRL should now have the certificate in status "removeFromCrl"
            forceDeltaCRL(authenticationToken, ca);
            crlEntry = fetchCRLEntry(cainfo, cert, true);
            assertNotNull("Unrevoked certificate should be on Delta CRL", crlEntry);
            assertEquals("Wrong revocation status on Delta CRL", CRLReason.REMOVE_FROM_CRL, crlEntry.getRevocationReason());
            
            // Generate a new Delta CRL. The certificate should still be there with removeFromCRL status
            forceDeltaCRL(authenticationToken, ca);
            crlEntry = fetchCRLEntry(cainfo, cert, true);
            assertNotNull("Unrevoked certificate should be on Delta CRL", crlEntry);
            assertEquals("Wrong revocation status on Delta CRL", CRLReason.REMOVE_FROM_CRL, crlEntry.getRevocationReason());
            
            // Generate a new Base CRL. The certificate should not be included.
            forceCRL(authenticationToken, ca);
            crlEntry = fetchCRLEntry(cainfo, cert, false);
            assertNull("Revoked certificate should have been removed after generating a new Base CRL", crlEntry);
            
            // Generate a new Delta CRL. The certificate should not be included.
            forceDeltaCRL(authenticationToken, ca);
            crlEntry = fetchCRLEntry(cainfo, cert, true);
            assertNull("Revoked certificate should no longer be included on Delta CRL after generating a new Base CRL", crlEntry);
            
            // Revoke the certificate again, and unrevoke it directly
            certificateStoreSession.setRevokeStatus(authenticationToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            certificateStoreSession.setRevokeStatus(authenticationToken, cert, new Date(), RevokedCertInfo.NOT_REVOKED);
            
            // Generate a new Base CRL. Unrevoked certificates should not appear on Base CRLs 
            forceCRL(authenticationToken, ca);
            crlEntry = fetchCRLEntry(cainfo, cert, false);
            assertNull("Unrevoked (removeFromCRL) certificates should never appears on Base CRLs", crlEntry);
        } finally {
            internalCertificateStoreSession.removeCertificatesBySubject("CN=testremovefromcrl");
        }
    }
    
    /**
     * Tests issuing a CRL from a CA with a SKID that is not generated with SHA1.
     * The CRL is checked to contain the correct AKID value.
     */
    @Test
    public void testNonSHA1KeyId() throws Exception {
        final String subcaname = "CrlCSTestSub";
        final String subcadn = "CN="+subcaname;
        try {
            // Create an external root ca certificate
            final KeyPair rootcakp = KeyTools.genKeys("1024", "RSA");
            final String rootcadn = "CN=CrlCSTestRoot";
            final X509Certificate rootcacert = CertTools.genSelfCert(rootcadn, 3650, null, rootcakp.getPrivate(), rootcakp.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, "BC", false);
            
            // Create sub ca
            final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(authenticationToken, subcaname, "1024");
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            X509CAInfo subcainfo = new X509CAInfo(subcadn, subcaname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, 365, CAInfo.SIGNEDBYEXTERNALCA, null, catoken);
            X509CA subca = new X509CA(subcainfo);
            subca.setCAToken(catoken);
            caSession.addCA(authenticationToken, subca);
            
            // Issue sub CA certificate with a non-standard SKID
            PublicKey subcapubkey = cryptoTokenMgmtSession.getPublicKey(authenticationToken, cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)).getPublicKey();
            Date firstDate = new Date();
            firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
            Date lastDate = new Date();
            lastDate.setTime(lastDate.getTime() + 365 * 24 * 60 * 60 * 1000);
            final SubjectPublicKeyInfo subcaspki = SubjectPublicKeyInfo.getInstance((ASN1Sequence) ASN1Primitive.fromByteArray(subcapubkey.getEncoded()));
            final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(rootcadn, false), new BigInteger(64, new Random(System.nanoTime())),
                    firstDate, lastDate, CertTools.stringToBcX500Name(subcadn, false), subcaspki);
            final AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(CertTools.getAuthorityKeyId(rootcacert));
            final SubjectKeyIdentifier ski = new SubjectKeyIdentifier(TEST_AKID); // Non-standard SKID. It should match the AKID in the CRL
            certbuilder.addExtension(Extension.authorityKeyIdentifier, true, aki);
            certbuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
            BasicConstraints bc = new BasicConstraints(true);
            certbuilder.addExtension(Extension.basicConstraints, true, bc);
            
            X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign);
            certbuilder.addExtension(Extension.keyUsage, true, ku);
            
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).setProvider(
                    BouncyCastleProvider.PROVIDER_NAME).build(rootcakp.getPrivate()), 20480);
            final X509CertificateHolder certHolder = certbuilder.build(signer);
            final X509Certificate subcacert = CertTools.getCertfromByteArray(certHolder.getEncoded(), BouncyCastleProvider.PROVIDER_NAME, X509Certificate.class);
            
            // Replace sub CA certificate with a sub CA cert containing the test AKID
            subcainfo = (X509CAInfo)caSession.getCAInfo(authenticationToken, subcaname);
            List<Certificate> certificatechain = new ArrayList<>();
            certificatechain.add(subcacert);
            certificatechain.add(rootcacert);
            subcainfo.setCertificateChain(certificatechain);
            subcainfo.setExpireTime(CertTools.getNotAfter(subcacert));
            caSession.editCA(authenticationToken, subcainfo);
            subca = (X509CA) caTestSessionRemote.getCA(authenticationToken, subcaname);
            assertArrayEquals("Wrong SKID in test CA.", TEST_AKID, CertTools.getSubjectKeyId(subca.getCACertificate()));
            
            // Create a base CRL and check the AKID
            int baseCrlNumber = crlStoreSession.getLastCRLNumber(subcadn, false) + 1;
            assertEquals("For a new CA, the next crl number should be 1.", 1, baseCrlNumber);
            crlCreateSession.generateAndStoreCRL(authenticationToken, subca, new ArrayList<RevokedCertInfo>(), -1, baseCrlNumber);
            final byte[] crl = crlStoreSession.getLastCRL(subcadn, false);
            checkCrlAkid(subca, crl);
            
            // Create a delta CRL and check the AKID
            int deltaCrlNumber = crlStoreSession.getLastCRLNumber(subcadn, false) + 1;
            assertEquals("Next CRL number should be 2 at this point.", 2, deltaCrlNumber);
            crlCreateSession.generateAndStoreCRL(authenticationToken, subca, new ArrayList<RevokedCertInfo>(), baseCrlNumber, deltaCrlNumber);
            final byte[] deltacrl = crlStoreSession.getLastCRL(subcadn, true); // true = get delta CRL
            checkCrlAkid(subca, deltacrl);
        } finally {
            // Remove everything created above to clean the database
            final Integer cryptoTokenId = cryptoTokenMgmtSession.getIdFromName(subcaname);
            if (cryptoTokenId != null) {
                CryptoTokenTestUtils.removeCryptoToken(authenticationToken, cryptoTokenId);
            }
            try {
                int caid = caSession.getCAInfo(authenticationToken, subcaname).getCAId();
                
                // Delete sub CA CRLs
                while (true) {
                    final byte[] crl = crlStoreSession.getLastCRL(subcadn, true); // delta CRLs
                    if (crl == null) { break; }
                    internalCertificateStoreSession.removeCRL(authenticationToken, CertTools.getFingerprintAsString(crl));
                }
                
                while (true) {
                    final byte[] crl = crlStoreSession.getLastCRL(subcadn, false); // base CRLs
                    if (crl == null) { break; }
                    internalCertificateStoreSession.removeCRL(authenticationToken, CertTools.getFingerprintAsString(crl));
                }
                
                // Delete sub CA
                caSession.removeCA(authenticationToken, caid);
            } catch (CADoesntExistsException cade) {
                // NOPMD ignore
            }
        }
    }

    private void checkCrlAkid(X509CA subca, final byte[] crl) throws Exception {
        assertNotNull(crl);
        
        // First, check that it is signed by the correct public key
        final X509CRL xcrl = CertTools.getCRLfromByteArray(crl);
        final PublicKey pubK = subca.getCACertificate().getPublicKey();
        xcrl.verify(pubK);
        
        // Check that the correct AKID is used
        final byte[] akidExtBytes = xcrl.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        ASN1InputStream octAis = new ASN1InputStream(new ByteArrayInputStream(akidExtBytes));
        DEROctetString oct = (DEROctetString) (octAis.readObject());
        ASN1InputStream keyidAis = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));
        AuthorityKeyIdentifier akid = AuthorityKeyIdentifier.getInstance(keyidAis.readObject());
        keyidAis.close();
        octAis.close();
        assertArrayEquals("Incorrect Authority Key Id in CRL.", TEST_AKID, akid.getKeyIdentifier());
    }
    
    private void forceDeltaCRL(AuthenticationToken admin, CA ca) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CRLException {
        final CRLInfo crlInfo = crlStoreSession.getLastCRLInfo(ca.getSubjectDN(), false);
        // if no full CRL has been generated we can't create a delta CRL
        if (crlInfo != null) {
            CAInfo cainfo = ca.getCAInfo();
            if (cainfo.getDeltaCRLPeriod() > 0) {
                internalCreateDeltaCRL(admin, ca, crlInfo.getLastCRLNumber(), crlInfo.getCreateDate().getTime());   
            }
        } 
    }
    
    private String forceCRL(AuthenticationToken admin, CA ca) throws CryptoTokenOfflineException,
            AuthorizationDeniedException {
        if (ca == null) {
            throw new EJBException("No CA specified.");
        }
        CAInfo cainfo = ca.getCAInfo();
        String ret = null;

        final String caCertSubjectDN; // DN from the CA issuing the CRL to be used when searching for the CRL in the database.
        {
            final Collection<Certificate> certs = cainfo.getCertificateChain();
            final Certificate cacert = !certs.isEmpty() ? certs.iterator().next() : null;
            caCertSubjectDN = cacert != null ? CertTools.getSubjectDN(cacert) : null;
        }
        // We can not create a CRL for a CA that is waiting for certificate response
        if (caCertSubjectDN != null && cainfo.getStatus() == CAConstants.CA_ACTIVE) {
            long crlperiod = cainfo.getCRLPeriod();
            // Find all revoked certificates for a complete CRL

            Collection<RevokedCertInfo> revcerts = certificateStoreSession.listRevokedCertInfo(caCertSubjectDN, -1);
            Date now = new Date();
            Date check = new Date(now.getTime() - crlperiod);
            AuthenticationToken archiveAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrlCreateSession.archive_expired"));
            for (RevokedCertInfo data : revcerts) {
                // We want to include certificates that was revoked after the last CRL was issued, but before this one
                // so the revoked certs are included in ONE CRL at least. See RFC5280 section 3.3.
                if (data.getExpireDate().before(check)) {
                    // Certificate has expired, set status to archived in the database
                    if (log.isDebugEnabled()) {
                        log.debug("Archiving certificate with fp=" + data.getCertificateFingerprint() + ". Free memory="
                                + Runtime.getRuntime().freeMemory());
                    }
                    certificateStoreSession.setStatus(archiveAdmin, data.getCertificateFingerprint(), CertificateConstants.CERT_ARCHIVED);
                }
            }
            // a full CRL
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            int fullnumber = crlStoreSession.getLastCRLNumber(certSubjectDN, false);
            int deltanumber = crlStoreSession.getLastCRLNumber(certSubjectDN, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
            int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;

            byte[] crlBytes = crlCreateSession.generateAndStoreCRL(admin, ca, revcerts, -1, nextCrlNumber);

            if (crlBytes != null) {
                ret = CertTools.getFingerprintAsString(crlBytes);
            }

        }

        return ret;
    }
    
    private byte[] internalCreateDeltaCRL(AuthenticationToken admin, CA ca, int baseCrlNumber, long baseCrlCreateTime)
            throws CryptoTokenOfflineException, AuthorizationDeniedException, CRLException {
        byte[] crlBytes = null;
        CAInfo cainfo = ca.getCAInfo();
        final String caCertSubjectDN;
        {
            final Collection<Certificate> certs = cainfo.getCertificateChain();
            final Certificate cacert = !certs.isEmpty() ? certs.iterator().next() : null;
            caCertSubjectDN = cacert != null ? CertTools.getSubjectDN(cacert) : null;
        }

        if ((baseCrlNumber == -1) && (baseCrlCreateTime == -1)) {
            CRLInfo basecrlinfo = crlStoreSession.getLastCRLInfo(caCertSubjectDN, false);
            baseCrlCreateTime = basecrlinfo.getCreateDate().getTime();
            baseCrlNumber = basecrlinfo.getLastCRLNumber();
        }
        // Find all revoked certificates
        Collection<RevokedCertInfo> revcertinfos = certificateStoreSession.listRevokedCertInfo(caCertSubjectDN, baseCrlCreateTime);
        if (log.isDebugEnabled()) {
            log.debug("Found " + revcertinfos.size() + " revoked certificates.");
        }
        // Go through them and create a CRL, at the same time archive expired certificates
        ArrayList<RevokedCertInfo> certs = new ArrayList<>();
        Iterator<RevokedCertInfo> iter = revcertinfos.iterator();
        while (iter.hasNext()) {
            RevokedCertInfo ci = iter.next();
            if (ci.getRevocationDate() == null) {
                ci.setRevocationDate(new Date());
            }
            certs.add(ci);
        }
        // create a delta CRL
        final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
        int fullnumber = crlStoreSession.getLastCRLNumber(certSubjectDN, false);
        int deltanumber = crlStoreSession.getLastCRLNumber(certSubjectDN, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;

        crlBytes = crlCreateSession.generateAndStoreCRL(admin, ca, certs, baseCrlNumber, nextCrlNumber);
        X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
        if (log.isDebugEnabled()) {
            log.debug("Created delta CRL with expire date: " + crl.getNextUpdate());
        }

        return crlBytes;
    }
    
    private X509CRLEntry fetchCRLEntry(final CAInfo cainfo, final Certificate cert, final boolean deltaCRL) throws CRLException {
        final byte[] crlBytes = crlStoreSession.getLastCRL(cainfo.getSubjectDN(), deltaCRL);
        final X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
        return crl.getRevokedCertificate(CertTools.getSerialNumber(cert));
    }

}
