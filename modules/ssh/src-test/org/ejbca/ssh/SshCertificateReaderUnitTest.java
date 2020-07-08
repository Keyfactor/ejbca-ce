/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificate.ssh.SshExtension;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ssh.assertion.SshAssert;
import org.ejbca.ssh.certificate.SshRsaCertificate;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;
import org.ejbca.ssh.keys.rsa.SshRsaPublicKey;
import org.ejbca.ssh.util.SshTestUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Includes unit tests for the SSH certificate reader. Note that if this test fails it invalidates nearly everything else, as this reader is then used
 * to verify the integrity of other certificates.
 *
 * @version $Id$
 */
public class SshCertificateReaderUnitTest {

    private static final Logger log = Logger.getLogger(SshRsaCertificate.class);

    // The output of an SSH RSA certificate produced by OpenSSH
    private static final String RSA_CERTIFICATE_BODY = "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg4Hbw/qGbHD3rtZTTecLT93+tEG/JLrMzCtPGGGFOocEAAAADAQABAAABAQC6sQfyd6Qcw/t6ueW2IFYtJ82eSB0Lj+4SiE57wlpXai2lwKqJKOJ+Uzb90l/ClpXJ397REhV5+z+UhywAkOWnL+UtFFvmIm1WowkVut58+4NWP8/T2io/NTLfP1wl6zcqHoDZxVDju62CYpN50TUSZWBCx2W4+jlLyZljZxOK2qdDpSuq9H8oj+DNSMCyhBA5Yfr4f0TJk2LBDficJJVXAplBOztcpECtE24IRMfJRo5m8bneCTMIVaDrT5zxPm1NrwuvllOolL/3cL5XjJ89VITSye80S5vcyxW+cq2lU9HyHBg2397FIC+q414IA95yTNGPb/dmmQFr3vFFYqjnAAAAAAAABTkAAAABAAAABWVqYmNhAAAAEwAAAAVlamJjYQAAAAZlamJjYTEAAAAAXsJSyAAAAABgojU2AAAAIwAAAA5zb3VyY2UtYWRkcmVzcwAAAA0AAAAJMTI3LjAuMC4xAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEAyl+zbTwY+yr4MQhURkpOlsIjWQiW5GnioZ21BNvZWjuMDJtB1ejbOVWc6E2LWzSIA0RUlfyzZKjBtTYIF/FGEn1OulNlTPTkOOfnqO9av5w570OL5F9MhIkRbG4WWtLkTgLW1OvclNMkvqsc6x2p9j3bakwRqxtxJohRk8EPEj6ECbJGxQGfno86WOrxTnOhOl0aoMG2r84i+xjf0P1WIlHARoYK5qy4jfveTqM57EccqaOdMNBTmDLxVNEwl0fITMlOl/IPQdjYIN+xr0oJRp4HE2QByA1usFmQyWFFuyt6MjKVklnEz/k+Go8gamBPJ0kg3dN1xxYtDhWkz7AqwQAAAQ8AAAAHc3NoLXJzYQAAAQBXg01RcCz1I9oeON8bOpz6BLIT4Q8DQdAmtWmYJuNMnR3cuCBtv66/k/sBvGKGic0gl2GuLHitMfD1npY4lfrJuj01xYdrt3mF1TXIHju0ivYQ/dMM5W7gePbuCo7zPZOj5OwNDAlNjiNX/R2BqyADNjsTw8vzBp1P2VX5nK8aJ55MS+LlfofOZU/Ey6cL6fyJ7T//sI4eULVsLLSP5oiXdnQA5GA93uikbmqLGWJC3iAPdSOPMSiCxp0cWoKrCgQNMA8YLfPLbQJnjGWU8HfKtcXMgbuYsIGbM5/k2CYNYCCloiUguyidRD40Td5+nNFJoIkVsoAlHUzi0OB91St2";
    // The output of an SSH EC certificate produced by OpenSSH, containing a custom extension
    private static final String EC_CERTIFICATE_BODY = "AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgcbdeNfLG+N120Fqlls2vBYj+3IWKaE3zO8wlWfr9Zf0AAAAIbmlzdHAzODQAAABhBEhwk8QN5sLpxVZWrTWRr66RO0JUKnji6Ewi/vV5eFFVR7y0DnlrX1QbSKUPSOwaFWzupW9hPJqDmuQlb03amTI+4UgqAQHCfjJwRJsTSQxeGehJkr5jNnO2uqPtNHloGQAAAAAAAAAAAAAAAQAAAAVlamJjYQAAABQAAAAGZWpiY2EwAAAABmVqYmNhMQAAAABe8NiMAAAAAGDQutgAAAAAAAAAqAAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAPY3VzdG9tRXh0ZW5zaW9uAAAADwAAAAtjdXN0b21WYWx1ZQAAAAAAAACIAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBEhwk8QN5sLpxVZWrTWRr66RO0JUKnji6Ewi/vV5eFFVR7y0DnlrX1QbSKUPSOwaFWzupW9hPJqDmuQlb03amTI+4UgqAQHCfjJwRJsTSQxeGehJkr5jNnO2uqPtNHloGQAAAIMAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAGgAAAAwGkyooNOtzFMN6USY9rQEHY1K4Lu6SMeynusjqD69gWJ5Hqnpu0tlBDlJvtZi2I2vAAAAMH7sTWdGZ3r/LcXZxWxOQErAiBi4wbpCauehyJFigmwQp9pIu/AO1g0tQjzPOWjX5w==";

    private static final String RSA_2048_CERTIFICATE_BODY = "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg5XCeFvniKnNbRZaclB83kTyF8zITCde4uRrv4mqesn4AAAADAQABAAABAQDiFqTBdKOWPeBeP1PiKSVy8ilfNChu5/6Z3iXu3Rdtg5ozu98IoAl4MtlklDdUDzvFkB+VPD/9gqHPKK8fTOhqgUPGoiCeZP3Ktr6NR53xd1QPQDeBvOMiYkPqQXziCQiVyL1WFzN616szrxsJ1Ni7WCHXcMTKOMruLv4es8FfB03wGDbBKVzMwo0JuZCicGg2pg/o8n9BPlzW6CvjUkmvUO3ycGKibPPFkiDgyuYynIbkMcmdShhY3XSOGB4UPeA3U4OiH6Z+09K9LqogWIcjxJeK0tObORd9QnQ4k1ba+/bbEfnFIQwLyzqXXPsPQ0Ud9upxVHD1lezRNE1DAIr9AAAAAAAAAAAAAAABAAAABWVqYmNhAAAAFAAAAAZlamJjYTAAAAAGZWpiY2ExAAAAAF7Q0HgAAAAAYLCytwAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQC8ajEtOvKxSPYSRL+A1y7Ye0baYHaR65KkzaT3U5XugHKHusvVPsDlRfSl598TsMjPQhbJt0O1SefMvXCbqdj776PWok5I1ScnLKJWRKzreeslEJZdcKTOUoT9Y5sg/LxC3xXwhIz+yLm8SbvQ7yQvPMmmlg5ldwccC8/0cua/25Vrjm0JhRjgxny65s2bNkClXXLmtevhvlQ7rXMQhpGmg5th156Ny/BUac7CQPEnDkRkhfsH8zKuh0NX19Y/93bwLsI7z+zP7CJJ11C0CpZl5yi2/8vqZUkufjRu/TH78EnLdCE/bkKcn0yyahG5BTh9dInrSclgCSiEPOYojvzjAAABFAAAAAxyc2Etc2hhMi0yNTYAAAEAj4/d9pKGGReo7B1ZbVBtHD9ftBfa5fjyPnuM8qbEMtYWgbx/MlCqVf2CL6VfJe2lvsg4ZZWvHyq0XBucFQqVHMekHJ71CymAs5/boGF4efLo56Ck6FF7tqM4dYmcO0aWRRQt3DyC24bLUZ4ZcdkyAgEm4EbTj9nPyvzbR57VsP/p+6WlszrGAHPwBlZ6my0g3cwPJSxwdV0USfMUIWooMIXLS7ocVZ7a8y+HF6qC2FGYIXYSgJuBaG5jlfXOojfKwA4tzwdy3ZziHxW50WDRkPrw6ZnXeRantJfMOhJ7ol9NSt1WcdkiAHqzDbEUpOz9UF0aSwxtIQYI7ONgl29a7w==";

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    /**
     * This test reads an RSA SSH certificate produced by OpenSSH. All values read from this method are arbitrary
     */
    @Test
    public void readOpenSshRsaCertificate()
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, SshKeyException {
        byte[] decoded = Base64.decode(RSA_CERTIFICATE_BODY.getBytes());
        SshCertificateReader sshCertificateReader = new SshCertificateReader(decoded);
        assertEquals("Certificate algorithm was incorrect", "ssh-rsa-cert-v01@openssh.com", sshCertificateReader.readString());
        assertNotNull("Nonce was not read correctly", sshCertificateReader.readByteArray());
        assertEquals("Public key exponent was not correct.", new BigInteger("65537"), sshCertificateReader.readBigInteger());
        String modulus = "23567621984854236439123955290273898347139858044867568814479599861877664633523775377263469684811824157777488364358124298508343280015239851936580297566868631869865803385432387670240804561355327051401135121758065676182682180249154405093880921091750331773370053535624808713451347307398517854893884588988511256805238858070177805298630025889725448674588754527895757222297017536150410687486311505474617797447794743923346734810311938119044426252076186405236100575053935282090954355784262734356677139024499878729961563365344619995262307882144069948169579756802587522825338753217866345055775967174769909605443503822377322719463";
        assertEquals("Public key modulus was not correct.", new BigInteger(modulus), sshCertificateReader.readBigInteger());
        assertEquals("Certificate serial number was not correct", "1337", Long.toUnsignedString(sshCertificateReader.readLong()));
        assertEquals("Certificate type was not correct", SshCertificateType.USER.getType(), sshCertificateReader.readInt());
        assertEquals("Key ID was not correct", "ejbca", sshCertificateReader.readString());
        // Principals are enclosed in a byte structure of their own.
        byte[] principalsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader principalReader = new SshCertificateReader(principalsBytes);
        Set<String> principals = new HashSet<>();
        while (principalReader.available() > 0) {
            principals.add(principalReader.readString());
        }
        Set<String> knownPrincipals = new HashSet<>(Arrays.asList("ejbca", "ejbca1"));
        principalReader.close();
        assertTrue("Principal was not correct", principals.containsAll(knownPrincipals));
        assertEquals("validAfter was not correct", 1589793480L, sshCertificateReader.readLong());
        assertEquals("validBefore was not correct", 1621243190L, sshCertificateReader.readLong());
        SshAssert.readAndVerifyCriticalOptions(sshCertificateReader, "127.0.0.1");
        // Extensions are enclosed in a byte structure of their own
        final Map<String, String> extensions = new HashMap<>();
        byte[] extensionsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader extensionsReader = new SshCertificateReader(extensionsBytes);
        while (extensionsReader.available() > 0) {
            String extensionName = extensionsReader.readString();
            String extensionValue = extensionsReader.readString();
            extensions.put(extensionName, extensionValue);
        }
        extensionsReader.close();
        final Map<String, byte[]> knownExtensions = SshTestUtils.getSshExtensionsMapWithExclusions(SshExtension.NO_PRESENCE_REQUIRED);
        assertEquals("Wrong number of extensions were decoded.", knownExtensions.size(), extensions.size());
        assertTrue("Reserved should not be used.", StringUtils.isEmpty(sshCertificateReader.readString()));

        byte[] signKeyBytes = sshCertificateReader.readByteArray();
        SshRsaPublicKey signKey = new SshRsaPublicKey(signKeyBytes);
        assertEquals("Sign key exponent was not correct.", new BigInteger("65537"), signKey.getPublicExponent());
        final String signKeyModulus = "25547329468668581448091006941867027738038190836229900309672701178314122728749422243355594308864841337990746855748272649185884412541200550449006024829082442250488432150471208064044260936743102331557333020586995952294528482648654154599499263029123976834734548773569895818099757157619987625766903165802506045539701449300859984248542541406038762425921481782854607434520219275274407070036111381046244934613665145523484940396940906944450608845898213677455683364009270884192632435384974143129022050881360746325810457273040614471865445431721678423582168005826886559053825728431347612687702230157772516471395624801586526563009";
        assertEquals("Sign key modulus was not correct.", new BigInteger(signKeyModulus), signKey.getModulus());

        // The signature also lives in its own structure
        byte[] signatureBytes = sshCertificateReader.readByteArray();
        assertEquals("Signature structure of incorrect size", 271, signatureBytes.length);
        SshCertificateReader signatureReader = new SshCertificateReader(signatureBytes);
        String signaturePrefix = signatureReader.readString();
        assertEquals("Incorrect signature prefix", "ssh-rsa", signaturePrefix);
        byte[] strippedSignatureBytes = signatureReader.readByteArray();
        assertEquals("Stripped Signature structure of incorrect size", getSignatureLength(signKey.getModulus()), strippedSignatureBytes.length);
        signatureReader.close();

        // The complete certificate body, minus the signature, i.e. that which was signed
        byte[] data = new byte[sshCertificateReader.array().length - (signatureBytes.length + 4)];
        System.arraycopy(sshCertificateReader.array(), 0, data, 0, data.length);
        assertTrue("Certificate signature could not be verified",
                verifyRsaSignature((RSAPublicKey) signKey.getPublicKey(), strippedSignatureBytes, signaturePrefix, data, true));
        sshCertificateReader.close();
    }

    /**
     * This test reads an RSA 2048 SSH certificate produced by OpenSSH. All values read from this method are arbitrary
     */
    @Test
    public void readOpenSshRsa2048Certificate()
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, SshKeyException {
        byte[] decoded = Base64.decode(RSA_2048_CERTIFICATE_BODY.getBytes());
        SshCertificateReader sshCertificateReader = new SshCertificateReader(decoded);
        assertEquals("Certificate algorithm was incorrect", "ssh-rsa-cert-v01@openssh.com", sshCertificateReader.readString());
        assertNotNull("Nonce was not read correctly", sshCertificateReader.readByteArray());
        assertEquals("Public key exponent was not correct.", new BigInteger("65537"), sshCertificateReader.readBigInteger());
        String modulus = "28541022886259081638340357443850069828981778614397148107095174634146585808869755921273502710614616667981980785475178595267991828395318095838624144174328493687569571385711895010665483906537566884943739279435141656945904394316897748052671941092071719868825119400945741752755114939205335463129867081408550395984231877251857633498050160150674301421632379237492758191133195811693990722284959683028406801434137450439199407153523323832059535013407734251239500534224423445017641120228481832652619161310002994046016970103249597443994962166272265400081355636506597490969562345292808417653209987242663365143741514312680726366973";
        assertEquals("Public key modulus was not correct.", new BigInteger(modulus), sshCertificateReader.readBigInteger());
        assertEquals("Certificate serial number was not correct", "0", Long.toUnsignedString(sshCertificateReader.readLong()));
        assertEquals("Certificate type was not correct", SshCertificateType.USER.getType(), sshCertificateReader.readInt());
        assertEquals("Key ID was not correct", "ejbca", sshCertificateReader.readString());
        // Principals are enclosed in a byte structure of their own.
        byte[] principalsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader principalReader = new SshCertificateReader(principalsBytes);
        Set<String> principals = new HashSet<>();
        while (principalReader.available() > 0) {
            principals.add(principalReader.readString());
        }
        Set<String> knownPrincipals = new HashSet<>(Arrays.asList("ejbca0", "ejbca1"));
        principalReader.close();
        assertTrue("Principal was not correct", principals.containsAll(knownPrincipals));
        assertEquals("validAfter was not correct", 1590743160L, sshCertificateReader.readLong());
        assertEquals("validBefore was not correct", 1622192823L, sshCertificateReader.readLong());
        // Critical options are enclosed in a byte structure of their own
        final Map<String, String> options = SshAssert.readCriticalOptions(sshCertificateReader);
        assertEquals("Incorrect critical options were read.", 0, options.size());
        // Extensions are enclosed in a byte structure of their own
        final Map<String, byte[]> extensions = new HashMap<>();
        byte[] extensionsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader extensionsReader = new SshCertificateReader(extensionsBytes);
        while (extensionsReader.available() > 0) {
            String extensionName = extensionsReader.readString();
            byte[] extensionValue = extensionsReader.readByteArray();
            extensions.put(extensionName, extensionValue);
        }
        extensionsReader.close();
        final Map<String, byte[]> knownExtensions = SshTestUtils.getSshExtensionsMapWithExclusions(SshExtension.NO_PRESENCE_REQUIRED);
        assertEquals("Wrong number of extensions were decoded.", knownExtensions.size(), extensions.size());
        assertTrue("Reserved should not be used.", StringUtils.isEmpty(sshCertificateReader.readString()));

        byte[] signKeyBytes = sshCertificateReader.readByteArray();
        SshRsaPublicKey signKey = new SshRsaPublicKey(signKeyBytes);
        assertEquals("Sign key exponent was not correct.", new BigInteger("65537"), signKey.getPublicExponent());
        final String signKeyModulus = "23785166608038845116032746741122004087121020393639867097553570258160243609972547991094992734931060304415272005297752144832612741617138414065365574970159269967919935080363655503699219828496450407677667848174555341386180677818208058193663098717616998136612820087668053179033544160618340850976413204713874648513789809442590791528856536960088790206800218410705639275585078633044727528795158572301070445907456376711472160860769709545642952079067210529123328883354600328342778020581199725648550643186199885711535717639992668171320106022334234062264355029132469207080966007593023306612100559686113591109148285912068796644579";
        assertEquals("Sign key modulus was not correct.", new BigInteger(signKeyModulus), signKey.getModulus());

        // The signature also lives in its own structure
        byte[] signatureBytes = sshCertificateReader.readByteArray();
        assertEquals("Signature structure of incorrect size", 276, signatureBytes.length);
        SshCertificateReader signatureReader = new SshCertificateReader(signatureBytes);
        String signaturePrefix = signatureReader.readString();
        assertEquals("Incorrect signature prefix", "rsa-sha2-256", signaturePrefix);
        byte[] strippedSignatureBytes = signatureReader.readByteArray();
        assertEquals("Stripped Signature structure of incorrect size", getSignatureLength(signKey.getModulus()), strippedSignatureBytes.length);
        signatureReader.close();

        // The complete certificate body, minus the signature, i.e. that which was signed
        byte[] data = new byte[sshCertificateReader.array().length - (signatureBytes.length + 4)];
        System.arraycopy(sshCertificateReader.array(), 0, data, 0, data.length);
        assertTrue("Certificate signature could not be verified",
                verifyRsaSignature((RSAPublicKey) signKey.getPublicKey(), strippedSignatureBytes, signaturePrefix, data, true));
        sshCertificateReader.close();
    }

    /**
     * This test reads an EC SSH certificate produced by OpenSSH. All values read from this method are arbitrary
     */
    @Test
    public void readOpenSshEcCertificate()
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException, InvalidKeySpecException, SshKeyException {
        byte[] decoded = Base64.decode(EC_CERTIFICATE_BODY.getBytes());
        SshCertificateReader sshCertificateReader = new SshCertificateReader(decoded);
        assertEquals("Certificate algorithm was incorrect", "ecdsa-sha2-nistp384-cert-v01@openssh.com", sshCertificateReader.readString());
        assertNotNull("Nonce was not read correctly", sshCertificateReader.readByteArray());
        String curveName = sshCertificateReader.readString();
        assertEquals("Curve name was not correct.", SshEcPublicKey.NISTP384, curveName);
        byte[] pointBytes = sshCertificateReader.readByteArray();
        ECParameterSpec ecParameterSpec = ECNamedCurveTable
                .getParameterSpec(AlgorithmTools.getEcKeySpecOidFromBcName(SshEcPublicKey.translateCurveName(curveName)));
        EllipticCurve ellipticCurve = EC5Util.convertCurve(ecParameterSpec.getCurve(), ecParameterSpec.getSeed());
        ECPoint ecPoint = KeyTools.decodeEcPoint(pointBytes, ellipticCurve);
        ECPoint knownPoint = new ECPoint(new BigInteger(
                "11149498690029991132497535399789746480089123096540896829523650125399993946922158672983030636376949942263159253113365"),
                new BigInteger(
                        "16766201897911275583566113562262925059747392579900791138787621834513613947952227341389795012146525597560280333248537"));
        assertEquals("EC Point was not correct", knownPoint, ecPoint);
        assertEquals("Certificate serial number was not correct", "0", Long.toUnsignedString(sshCertificateReader.readLong()));
        assertEquals("Certificate type was not correct", SshCertificateType.USER.getType(), sshCertificateReader.readInt());
        assertEquals("Key ID was not correct", "ejbca", sshCertificateReader.readString());
        // Principals are enclosed in a byte structure of their own.
        byte[] principalsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader principalReader = new SshCertificateReader(principalsBytes);
        Set<String> principals = new HashSet<>();
        while (principalReader.available() > 0) {
            principals.add(principalReader.readString());
        }
        Set<String> knownPrincipals = new HashSet<>(Arrays.asList("ejbca0", "ejbca1"));
        principalReader.close();
        assertTrue("Principal was not correct", principals.containsAll(knownPrincipals));
        assertEquals("validAfter was not correct", 1592842380L, sshCertificateReader.readLong());
        assertEquals("validBefore was not correct", 1624292056L, sshCertificateReader.readLong());
        // Critical options are enclosed in a byte structure of their own
        final Map<String, String> options = SshAssert.readCriticalOptions(sshCertificateReader);
        assertEquals("Incorrect critical options were read.", 0, options.size());
        // Extensions are enclosed in a byte structure of their own
        final Map<String, byte[]> extensions = new HashMap<>();
        byte[] extensionsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader extensionsReader = new SshCertificateReader(extensionsBytes);
        while (extensionsReader.available() > 0) {
            String extensionName = extensionsReader.readString();
            SshCertificateReader extensionValueReader = new SshCertificateReader(extensionsReader.readByteArray());
            byte[] extensionValue;
            if (extensionValueReader.available() > 0) {
                extensionValue = extensionValueReader.readByteArray();
            } else {
                extensionValue = new byte[0];
            }
            extensions.put(extensionName, extensionValue);
            extensionValueReader.close();
        }
        extensionsReader.close();
        final Map<String, byte[]> knownExtensions = SshTestUtils.getSshExtensionsMapWithExclusions(SshExtension.NO_PRESENCE_REQUIRED);
        knownExtensions.put("customExtension", "customValue".getBytes());
        assertEquals("Wrong number of extensions were decoded.", knownExtensions.size(), extensions.size());
        assertArrayEquals("Custom extension was not decoded correctly.", extensions.get("customExtension"), "customValue".getBytes());
        assertTrue("Reserved should not be used.", StringUtils.isEmpty(sshCertificateReader.readString()));

        byte[] signKeyBytes = sshCertificateReader.readByteArray();
        SshEcPublicKey signKey = new SshEcPublicKey(signKeyBytes);
        assertEquals("Signer Curve name was not correct.", SshEcPublicKey.NISTP384, signKey.getCurveName());
        ECPoint signerEcPoint = ((ECPublicKey) signKey.getPublicKey()).getW();
        ECPoint knownSignerEcPoint = new ECPoint(new BigInteger(
                "11149498690029991132497535399789746480089123096540896829523650125399993946922158672983030636376949942263159253113365"),
                new BigInteger(
                        "16766201897911275583566113562262925059747392579900791138787621834513613947952227341389795012146525597560280333248537"));
        assertEquals("Signer EC point was incorrect", knownSignerEcPoint, signerEcPoint);
        // The signature also lives in its own structure
        byte[] signatureBytes = sshCertificateReader.readByteArray();
        assertEquals("Signature structure of incorrect size", 131, signatureBytes.length);
        SshCertificateReader signatureReader = new SshCertificateReader(signatureBytes);
        String signaturePrefix = signatureReader.readString();
        assertEquals("Incorrect signature prefix", "ecdsa-sha2-nistp384", signaturePrefix);
        byte[] strippedSignatureBytes = signatureReader.readByteArray();
        signatureReader.close();

        // The complete certificate body, minus the signature, i.e. that which was signed
        byte[] data = new byte[sshCertificateReader.array().length - (signatureBytes.length + 4)];
        System.arraycopy(sshCertificateReader.array(), 0, data, 0, data.length);
        assertTrue("Certificate signature could not be verified",
                SshAssert.verifyEcSignature((ECPublicKey) signKey.getPublicKey(), strippedSignatureBytes, curveName, data));
        sshCertificateReader.close();
    }

    /**
     *
     * @param modulus the modulus of an RSA key
     * @return the expected signature length
     */
    private int getSignatureLength(BigInteger modulus) {
        int length = modulus.bitLength() / 8;
        int mod = modulus.bitLength() % 8;
        if (mod != 0) {
            length++;
        }
        return length;
    }

    private boolean verifyRsaSignature(RSAPublicKey publicKey, byte[] signatureBytes, String signatureAlgorithm, byte[] data, boolean allowCorrect)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature;
        switch (signatureAlgorithm) {
        case "rsa-sha2-256":
            signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
            break;
        case "rsa-sha2-512":
            signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA512_WITH_RSA);
            break;
        default:
            signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            break;
        }
        signature.initVerify(publicKey);
        signature.update(data);
        int expectedLength = getSignatureLength(publicKey.getModulus());
        int signatureLength = signatureBytes.length;
        boolean corrected = false;
        byte[] original = signatureBytes;
        if (signatureBytes.length < expectedLength) {
            if (log.isDebugEnabled()) {
                log.debug("No Padding Detected: Expected signature length of " + expectedLength + " (modulus=" + publicKey.getModulus().bitLength()
                        + ") but got " + signatureBytes.length);
            }
            byte[] tmp = new byte[expectedLength];
            System.arraycopy(signature, 0, tmp, expectedLength - signatureBytes.length, signatureBytes.length);
            signatureBytes = tmp;
            corrected = true;
        }
        boolean result = false;
        try {
            result = signature.verify(signatureBytes);
        } catch (SignatureException e) {
            if (!allowCorrect) {
                throw e;
            }
            if (log.isDebugEnabled()) {
                log.debug("Signature failed. Falling back to raw signature data.");
            }
        }
        if (!result) {
            if (corrected) {
                result = verifyRsaSignature(publicKey, original, signatureAlgorithm, data, false);
            }
            if (!result) {
                if (log.isDebugEnabled() && Boolean.getBoolean("maverick.verbose")) {
                    log.debug("JCE Reports Invalid Signature: Expected signature length of " + expectedLength + " (modulus="
                            + publicKey.getModulus().bitLength() + ") but got " + signatureLength);
                }
            }
        }
        return result;
    }
}
