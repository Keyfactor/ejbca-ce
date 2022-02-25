package org.cesecore.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.jcajce.JcaITSPublicVerificationKey;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_Encrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Data_Signed;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import org.bouncycastle.oer.its.ieee1609dot2.EncryptedData;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Duration;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ValidityPeriod;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import org.bouncycastle.util.encoders.Hex;

public class ECAUtils {

    public static final String SHA_256_EMPTY_STRING = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public static final String SHA_384_EMPTY_STRING = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c"
                                                            + "0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    
    public static byte[] getEmptyStringHash(String algorithm) {
        if(algorithm.contains("SHA256")) {
            return Hex.decode(SHA_256_EMPTY_STRING);
        }
        if(algorithm.contains("SHA384")) {
            return Hex.decode(SHA_384_EMPTY_STRING);
        }
        return null;
    }
    
    public static HashedId8 generateHashedId8(byte[] input) {
        //HashedId is always calculated using SHA256
        byte[] output = new byte[8];
        System.arraycopy(generateHash("SHA256", input), 0, output, 0, 8);
        return new HashedId8(output);
    }
    
    public static byte[] generateHash(byte[] input) {
        return generateHash("SHA256", input);
    }
    
    public static PublicKey getPublicKeyFromCertificate(ITSCertificate certificate) {
        PublicVerificationKey publicVerificationKey =
                (PublicVerificationKey) certificate.toASN1Structure()
                    .getToBeSignedCertificate().getVerificationKeyIndicator().getValue();
        return new JcaITSPublicVerificationKey.Builder().build(publicVerificationKey).getKey();
    }
    
    public static byte[] generateHash(String algorithm, byte[] input) {
        if(input==null) {
            getEmptyStringHash(algorithm);
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        digest.update(input);
        return digest.digest();
    }
    
    public static byte[] concatenateBytes(byte[] input1, byte[] input2) {
        byte[] output = new byte[input1.length + input2.length];
        System.arraycopy(input1, 0, output, 0, input1.length);
        System.arraycopy(input1, 0, output, input1.length, input2.length);
        return output;
    }
    
    public static int getSigntureChoice(PublicKey publicKey) {
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        ASN1ObjectIdentifier curveID = 
                ASN1ObjectIdentifier.getInstance(pkInfo.getAlgorithm().getParameters());
        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return Signature.ecdsaNistP256Signature;
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return Signature.ecdsaBrainpoolP256r1Signature;
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return Signature.ecdsaBrainpoolP384r1Signature;
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }
    }
    
    public static SignedData parseOerEncodedSignedData(byte[] oerEncodedSignedData) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncodedSignedData));
        try {
            return SignedData.getInstance(oerIn.parse(IEEE1609dot2.SignedData.build()));
        } catch (IOException e) {
            throw new IllegalStateException("SignedData is malformed: " + e);
        }
    }
    
    public static SignedData parseOerEncodedWrappedSignedData(byte[] oerEncodedSignedData) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncodedSignedData));
        try {
            Ieee1609Dot2Content content = EtsiTs103097Data_Signed.getInstance(
                    oerIn.parse(EtsiTs103097Module.EtsiTs103097Data_Signed.build())).getContent();
            if (content.getChoice() != Ieee1609Dot2Content.signedData)
            {
                throw new IllegalStateException("EtsiTs103097Data-Signed did not have signed data content");
            }
            return SignedData.getInstance(content.getContent());
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped SignedData is malformed: " + e);
        }
    }
    
    public static EncryptedData parseOerEncodedWrappedEncryptedData(byte[] oerEncodedEncryptedData) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncodedEncryptedData));
        try {
            Ieee1609Dot2Content content = EtsiTs103097Data_Encrypted.getInstance(
                    oerIn.parse(EtsiTs103097Module.EtsiTs103097Data_Encrypted.build())).getContent();
            if (content.getChoice() != Ieee1609Dot2Content.encryptedData)
            {
                throw new IllegalStateException("EtsiTs103097Data_Encrypted did not have encrypted data content");
            }
            return EncryptedData.getInstance(content.getContent());
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped SignedData is malformed: " + e);
        }
    }
    
    public static DEROctetString parseOerEncodedWrappedUnsecuredData(byte[] oerEncodedUnsecuredData) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncodedUnsecuredData));
        try {
            Ieee1609Dot2Content content = EtsiTs103097Data_Signed.getInstance(
                    oerIn.parse(EtsiTs103097Module.EtsiTs103097Data_Unsecured.build())).getContent();
            if (content.getChoice() != Ieee1609Dot2Content.unsecuredData)
            {
                throw new IllegalStateException("Wrong data content in Ieee1609Dot2Content.");
            }
            return (DEROctetString) content.getContent();
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped Ieee1609Dot2Content is malformed: " + e);
        }
    }

    public static HashedId8 generateHashedId8(ITSCertificate caCertificate) {
        // TODO properly encode certificate
        // tbsCertificate -> compressed-y-0 or 1 -> multiple HashedId8? -> no +/- y coord, unique hash
        // signature -> r or x-only
        return generateHashedId8(OEREncoder.toByteArray(caCertificate.toASN1Structure(), 
                                        IEEE1609dot2.ExplicitCertificate.build()));
    }
    
    public static Date getExpiryDate(ITSCertificate certificate) {
        return getExpiryDate(certificate.toASN1Structure().getToBeSignedCertificate().getValidityPeriod());
    }
    
    public static Date getExpiryDate(ValidityPeriod validityPeriod) {
        long validity = getValidityInSeconds(validityPeriod);
        long startTime = validityPeriod.getTime32().toUnixMillis();
        return new Date(startTime + validity);
    }
    
    public static long getValidityInSeconds(ValidityPeriod validity) {
        long result = validity.getDuration().getValue();
        switch(validity.getDuration().getChoice()) {
            case Duration.microseconds:
                return result/1000_000; 
            case Duration.milliseconds:
                return result/1000; 
            case Duration.seconds:
                return result; 
            case Duration.minutes:
                return result*60; 
            case Duration.hours:
                return result*3600; 
            case Duration.sixtyHours:
                return result*3600*60; 
            case Duration.years:
                return result*SimpleTime.SECONDS_PER_YEAR_IEEE;
            default:
                throw new IllegalArgumentException("Invalid duration period: " 
                                + validity.getDuration().getChoice());
        }
        
    }
    
    
    public static ITSCertificate parseItsCertificate(byte[] encodedCertificate) {
        if(encodedCertificate==null) {
            return null;
        }
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(encodedCertificate));
        CertificateBase content;
        try {
            content = CertificateBase.getInstance(
                    oerIn.parse(IEEE1609dot2.CertificateBase.build()));
        } catch (IOException e) {
            throw new IllegalStateException("Malformed encoded certificate bytes.");
        }
        return new ITSCertificate(content);
    }
    
}
