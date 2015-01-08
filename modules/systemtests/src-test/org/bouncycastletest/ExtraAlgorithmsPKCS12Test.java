package org.bouncycastletest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * This test verifies that GOST3410 and DSTU4145 are working in BouncyCastle.
 * It doesn't actually test EJBCA. Note that these algorithms must be configured
 * in EJBCA.
 */
public class ExtraAlgorithmsPKCS12Test {
    
    private static final Logger log = Logger.getLogger(ExtraAlgorithmsPKCS12Test.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void testP12KeystoreGOST3410() throws Exception {
        log.debug("GOST3410 configured: "+(AlgorithmTools.isGost3410Enabled() ? "YES" : "NO"));
        assumeTrue(AlgorithmTools.isGost3410Enabled());
        log.trace(">testP12KeystoreGOST3410()");
        
        String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
        assertNotNull("curve B is not configued!", keyspec);
        
        AlgorithmParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(keyspec);
        assertNotNull(spec);
        testAlgorithm("ECGOST3410", AlgorithmConstants.KEYALGORITHM_ECGOST3410, AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410, spec);
        
        log.trace("<testP12KeystoreGOST3410()");
    }
    
    /**
     * Tries to create a PKCS#12 file with a DSTU4145 cert. 
     * This test requires a patched BouncyCastle.
     */
    @Test
    public void testP12KeystoreDSTU4145() throws Exception {
        log.debug("DSTU4145 configured: "+(AlgorithmTools.isDstu4145Enabled() ? "YES" : "NO"));
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        log.trace(">testP12KeystoreDSTU4145()");
        
        String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
        assertNotNull("curve 233 is not configued!", keyspec);
        
        AlgorithmParameterSpec spec = KeyTools.dstuOidToAlgoParams(keyspec);
        assertNotNull(spec);
        testAlgorithm("DSTU4145", AlgorithmConstants.KEYALGORITHM_DSTU4145, AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145, spec);
        
        log.trace("<testP12KeystoreDSTU4145()");
    }
    
    private static void testAlgorithm(String algInstance, String keyAlg, String sigAlg, AlgorithmParameterSpec paramSpec) throws Exception {
        // We first create a keypair and a certificate to add to our PKCS12 file
        KeyStore ks = null;
        KeyPair newsignkeys = null;
        Certificate[] certchain = new Certificate[1];
        String ksbytes = null;
        
        // Keys
        final KeyPairGenerator keygen = KeyPairGenerator.getInstance(algInstance, "BC");
        assertNotNull(keygen);
        keygen.initialize(paramSpec, new SecureRandom());
        newsignkeys = keygen.generateKeyPair();
        assertNotNull(newsignkeys);
        
        // Certificate
        certchain[0] = generateSelfCertificate(newsignkeys.getPrivate(), newsignkeys.getPublic(), algInstance, sigAlg);

        assertEquals(newsignkeys.getPublic().getAlgorithm(), keyAlg);
        
        // Now, we create a PKCS12 keystore
        ks = KeyStore.getInstance("PKCS12", "BC");
        assertNotNull(ks);
        ks.load(null, null);
        ks.setKeyEntry("privatesignkeyalias", newsignkeys.getPrivate(), null, certchain);
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        ks.store(baos, "foo123".toCharArray());
        ksbytes = new String(base64Encode(baos.toByteArray()));
        baos.close();

        // Uncomment to write to a file to check that everything is correct with openssl/cryptonit
        /*DataOutputStream out = new DataOutputStream(new FileOutputStream("pkcs12TestECGOST3410"));
        try {
            out.write(Base64.decode(ksbytes.getBytes()));
        } finally {
            out.close();
        }*/
        
        // We try to initiate a new keystore from the one we have just created
        KeyStore tryReadKS = KeyStore.getInstance("PKCS12", "BC");
        assertNotNull(tryReadKS);
        
        tryReadKS.load(new java.io.ByteArrayInputStream(Base64.decode(ksbytes.getBytes())),"foo123".toCharArray());
    }

    private static X500Name makeName(String cn) {
        final X500NameBuilder namebuild = new X500NameBuilder(BCStyle.INSTANCE);
        namebuild.addRDN(BCStyle.CN, cn);
        return namebuild.build();
    }

    private static X509Certificate generateSelfCertificate(PrivateKey privKey, PublicKey pubKey, String algInstance, String sigAlg) throws Exception {
        // Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
        // bean is created.
        byte[] serno = new byte[8];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new Date().getTime());
        random.nextBytes(serno);
        
        Date firstDate = new Date();
        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
        Date lastDate = new Date();
        // validity in days = validity*24*60*60*1000 milliseconds
        lastDate.setTime(lastDate.getTime() + (36500 * (24 * 60 * 60 * 1000)));

        X500Name issuer = makeName("Some Issuer");
        X500Name subject = makeName("Some User");
        
        // Transform the PublicKey to be sure we have it in a format that the X509 certificate generator handles, it might be 
        // a CVC public key that is passed as parameter
        ECPublicKey ecpk = (ECPublicKey)pubKey;
        ECPublicKeySpec ecspec = new ECPublicKeySpec(ecpk.getW(), ecpk.getParams());
        PublicKey publicKey = KeyFactory.getInstance(algInstance).generatePublic(ecspec);
        
        ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(publicKey.getEncoded()));
        ASN1Sequence spkiAsn1;
        try {
            spkiAsn1 = (ASN1Sequence)ais.readObject();
        } finally {
            ais.close();
        }
        
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(spkiAsn1);
        
        
        // Start building the certificate
        X509v3CertificateBuilder certbuild = new X509v3CertificateBuilder(issuer, new BigInteger(serno).abs(), firstDate, lastDate, subject, spki);
        
        
        // Basic constraints is always critical and MUST be present at least in CA-certificates.
        BasicConstraints bc = new BasicConstraints(true);
        certbuild.addExtension(X509Extension.basicConstraints, true, bc);
        
        // Put critical KeyUsage in CA-certificates
        X509KeyUsage ku = new X509KeyUsage(6);
        certbuild.addExtension(X509Extension.keyUsage, true, ku);
        
        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Firefox.
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki.getEncoded());
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(spki.getEncoded());
        certbuild.addExtension(X509Extension.subjectKeyIdentifier, false, ski);
        certbuild.addExtension(X509Extension.authorityKeyIdentifier, false, aki);
        
        ContentSigner sigGen = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privKey), 20480);
        
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certbuild.build(sigGen));
    }

    /**
     * Base64 with added new lines every 64 characters.
     */
    private static byte[] base64Encode(final byte[] data) {
        byte[] bytes = Base64.encode(data);

        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        for (int i = 0; i < bytes.length; i += 64) {
            if ((i + 64) < bytes.length) {
                os.write(bytes, i, 64);
                os.write('\n');
            } else {
                os.write(bytes, i, bytes.length - i);
            }
        }
        bytes = os.toByteArray();

        return bytes;
    }

}
