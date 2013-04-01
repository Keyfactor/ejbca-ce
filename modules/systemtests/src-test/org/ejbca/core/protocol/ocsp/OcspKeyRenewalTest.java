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
package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.standalone.StandaloneOcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.DummyCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.protocol.ocsp.standalone.OcspKeyRenewalProxySessionRemote;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class OcspKeyRenewalTest {

    private OcspKeyRenewalProxySessionRemote ocspKeyRenewalProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspKeyRenewalProxySessionRemote.class);
    private StandaloneOcspResponseGeneratorTestSessionRemote standaloneOcspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(StandaloneOcspResponseGeneratorTestSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
  
    /**
     * This is the most basic sanity test possible. Key renewal is tested with a DummyCryptoToken in place of a PKCS11, and the web service 
     * is replaced by a mock (as defined in OcspKeyRenewalProxySessionBean) that parrots the expected reply. 
     * 
     */
    @Test
    public void testKeyRenewal() throws KeyStoreException, CryptoTokenOfflineException, InstantiationException, OCSPException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, IllegalStateException,
            NoSuchProviderException, OperatorCreationException, CertificateException, IOException {
        //Set a mock CryptoToken in the cache
        final String testAlias = "testAlias";
        Map<Integer, CryptoTokenAndChain> newCache = new HashMap<Integer, CryptoTokenAndChain>();
        CryptoToken dummyCryptoToken = new DummyCryptoToken();
        KeyPair caKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        //Generate a fake CA Certificate
        String caDn = "CN=OcspDefaultTestCA";
        X509Certificate caCert = CertTools.genSelfCert(caDn, 365, null, caKeys.getPrivate(), caKeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        //Generate the signer certificate
        Date firstDate = new Date();
        // Set starting date to tomorrow
        firstDate.setTime(firstDate.getTime() + (24 * 3600 * 1000));
        Date lastDate = new Date();
        // Set Expiry in two days
        lastDate.setTime(lastDate.getTime() + ((2 * 24 * 60 * 60 * 1000)));
        BigInteger serno = SernoGeneratorRandom.instance().getSerno();
        SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence)ASN1Primitive.fromByteArray(caKeys.getPublic().getEncoded()));
        final X509NameEntryConverter converter = new X509DefaultEntryConverter();
        X500Name caName =  CertTools.stringToBcX500Name(caDn, converter, false);
        ocspKeyRenewalProxySession.setManagementCaKeyPair(caKeys);
        ocspKeyRenewalProxySession.setCaDn(caDn);
        X500Name signerName = CertTools.stringToBcX500Name("CN=ocspTestSigner", converter, false);
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(caName, serno, firstDate, lastDate, signerName, pkinfo);
        final ContentSigner signer = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).build(caKeys.getPrivate());
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        final X509Certificate cert = (X509Certificate)CertTools.getCertfromByteArray(certHolder.getEncoded());     
        
        X509Certificate[] certchain = {cert, caCert};
        try {
            cert.verify(caCert.getPublicKey());
        } catch (SignatureException e) {
            throw new RuntimeException();
        }
        CryptoTokenAndChain testTokenAndChain = new CryptoTokenAndChain(dummyCryptoToken, certchain, testAlias);
        newCache.put(Integer.valueOf(1337), testTokenAndChain);
        standaloneOcspResponseGeneratorTestSession.replaceTokenAndChainCache(newCache);
        Collection<CryptoTokenAndChain> oldValues = standaloneOcspResponseGeneratorTestSession.getCacheValues();
        if(oldValues.size() < 1) {
            throw new RuntimeException("Cache contains no values. Something is messed up.");
        }
        if(oldValues.size() > 1) {
            throw new RuntimeException("Cache contains more than one value. Something is messed up.");
        }
        ocspKeyRenewalProxySession.renewKeyStores("CN=ocspTestSigner");
        List<CryptoTokenAndChain> newValues = new ArrayList<CryptoTokenAndChain>(standaloneOcspResponseGeneratorTestSession.getCacheValues());
        //Make sure that cache contains one and only one value
        assertEquals("Cache contains a different amount of values after rekeying than before. This indicates a test failure", oldValues.size(), newValues.size());
        //Make check that the certificate has changed (sanity check)
        X509Certificate newSigningCertificate = newValues.get(0).getChain()[0];
        assertNotEquals("The same certificate was returned after the renewal process. Key renewal failed", cert.getSerialNumber(),
                newSigningCertificate.getSerialNumber());
        //Make sure that the new certificate is signed by the CA certificate
        try {
            newSigningCertificate.verify(caCert.getPublicKey());
        } catch (SignatureException e) {
            fail("The new signing certificate was not signed correctly.");
        }
    }

}
