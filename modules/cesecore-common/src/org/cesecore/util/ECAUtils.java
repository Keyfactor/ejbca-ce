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
import org.bouncycastle.its.jcajce.JceITSPublicEncryptionKey;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.its.etsi102941.EtsiTs102941Data;
import org.bouncycastle.oer.its.etsi102941.EtsiTs102941DataContent;
import org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import org.bouncycastle.oer.its.ieee1609dot2.EncryptedData;
import org.bouncycastle.oer.its.ieee1609dot2.HashedData;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import org.bouncycastle.oer.its.ieee1609dot2.Opaque;
import org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.VerificationKeyIndicator;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Duration;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP256Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EcdsaP384Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point256;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point384;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.ValidityPeriod;
import org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941MessagesCa;
import org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
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
        System.arraycopy(generateHash("SHA256", input), 24, output, 0, 8); // low order 8 bytes
        return new HashedId8(output);
    }
    
    public static byte[] generateHash(byte[] input) {
        return generateHash("SHA256", input);
    }
    
    public static byte[] caculateRequestHash(byte[] input) {
        byte result[] = new byte[16];
        System.arraycopy(generateHash("SHA256", input), 0, result, 0, 16); // left most 16 bytes
        return result;
    }
    
    public static PublicKey getVerificationKeyFromCertificate(ITSCertificate certificate) {
        PublicVerificationKey publicVerificationKey =
                (PublicVerificationKey) certificate.toASN1Structure()
                    .getToBeSigned().getVerifyKeyIndicator().getVerificationKeyIndicator();
        return new JcaITSPublicVerificationKey.Builder().build(publicVerificationKey).getKey();
    }
    
    public static PublicKey getEncryptionKeyFromCertificate(ITSCertificate certificate) {
        PublicEncryptionKey publicEncryptionKey =
                (PublicEncryptionKey) certificate.toASN1Structure()
                    .getToBeSigned().getEncryptionKey();
        return new JceITSPublicEncryptionKey.Builder().build(publicEncryptionKey).getKey();
    }
    
    public static PublicVerificationKey createVerificationKey(PublicKey publicKey) {
        return new JcaITSPublicVerificationKey.Builder().build(publicKey).toASN1Structure();
    }
    
    public static PublicEncryptionKey createEncryptionKey(PublicKey publicKey) {
        return new JceITSPublicEncryptionKey.Builder().build(publicKey).toASN1Structure();
    }
    
    public static byte[] encodeWrappedData102941(EtsiTs102941DataContent data102941) {
        EtsiTs102941Data wrappedData102941 = new EtsiTs102941Data(new Version(1), data102941);
        byte[] encodedData102941 = OEREncoder.toByteArray(wrappedData102941, 
                EtsiTs102941MessagesCa.EtsiTs102941Data.build());
        return encodedData102941;
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
            Ieee1609Dot2Content content = EtsiTs103097DataSigned.getInstance(
                    oerIn.parse(EtsiTs103097Module.EtsiTs103097Data_Signed.build())).getContent();
            if (content.getChoice() != Ieee1609Dot2Content.signedData)
            {
                throw new IllegalStateException("EtsiTs103097Data-Signed did not have signed data content");
            }
            return SignedData.getInstance(content.getIeee1609Dot2Content());
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped SignedData is malformed: " + e);
        }
    }
    
    public static SignedData parseOerEncodedWrappedSignedExtenalData(byte[] oerEncodedSignedExtData) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncodedSignedExtData));
        try {
            Ieee1609Dot2Content content = EtsiTs103097DataSigned.getInstance(
                    oerIn.parse(EtsiTs103097Module.EtsiTs103097Data_SignedExternalPayload.build())).getContent();
            if (content.getChoice() != Ieee1609Dot2Content.signedData)
            {
                throw new IllegalStateException(
                        "EtsiTs103097Data-SignedExternalPayload did not have signed data content");
            }
            return SignedData.getInstance(content.getIeee1609Dot2Content());
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped SignedExternalPayload is malformed: " + e);
        }
    }
    
    public static EncryptedData parseOerEncodedWrappedEncryptedData(byte[] oerEncodedEncryptedData) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncodedEncryptedData));
        try {
            Ieee1609Dot2Content content = EtsiTs103097DataEncrypted.getInstance(
                    oerIn.parse(EtsiTs103097Module.EtsiTs103097Data_Encrypted.build())).getContent();
            if (content.getChoice() != Ieee1609Dot2Content.encryptedData)
            {
                throw new IllegalStateException("EtsiTs103097DataEncrypted did not have encrypted data content");
            }
            return EncryptedData.getInstance(content.getIeee1609Dot2Content());
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped EncryptedData is malformed: " + e);
        }
    }
    
    public static byte[] parseOerEncodedWrappedUnsecuredData(byte[] oerEncodedUnsecuredData) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncodedUnsecuredData));
        try {
            Ieee1609Dot2Content content = EtsiTs103097DataSigned.getInstance(
                    oerIn.parse(EtsiTs103097Module.EtsiTs103097Data_Unsecured.build())).getContent();
            if (content.getChoice() != Ieee1609Dot2Content.unsecuredData)
            {
                throw new IllegalStateException("Wrong data content in Ieee1609Dot2Content.");
            } 
            return ((Opaque) content.getIeee1609Dot2Content()).getContent();
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped Ieee1609Dot2Content is malformed: " + e);
        }
    }
    
    public static EtsiTs102941DataContent parseOerEncodedWrapped102941Data(byte[] oerEncoded102941Data) {
        OERInputStream oerIn = new OERInputStream(new ByteArrayInputStream(oerEncoded102941Data));
        try {
            EtsiTs102941DataContent content = EtsiTs102941Data.getInstance(
                    oerIn.parse(EtsiTs102941MessagesCa.EtsiTs102941Data.build())).getContent();
            return content;
        } catch (IOException e) {
            throw new IllegalStateException("Wrapped EtsiTs102941DataContent is malformed: " + e);
        }
    }

    public static HashedId8 generateHashedId8(ITSCertificate certificate) {
        ITSCertificate hashableCertificate = getHashableCertificate(certificate);
        return generateHashedId8(OEREncoder.toByteArray(hashableCertificate.toASN1Structure(), 
                                        IEEE1609dot2.ExplicitCertificate.build()));
    }
    
    public static byte[] generateHash(ITSCertificate certificate) {
        ITSCertificate hashableCertificate = getHashableCertificate(certificate);
        return generateHash(OEREncoder.toByteArray(hashableCertificate.toASN1Structure(), 
                                        IEEE1609dot2.ExplicitCertificate.build()));
    }
    
    /**
     * Encoding consideration: section 6.4.3 in IEEE 1609.2-2016, page 60
     * properly encode certificate
     * tbsCertificate -> compressed-y-0 or 1 -> multiple HashedId8? -> no +/- y coord, unique hash
     * signature -> r or x-only
     * 
     * @param certificate
     * @return
     */
    public static ITSCertificate getHashableCertificate(ITSCertificate certificate) {
        Signature signature = certificate.toASN1Structure().getSignature();
        Signature modifiedSignature = null;
        if(signature.getChoice()<Signature.ecdsaBrainpoolP384r1Signature) {
            EcdsaP256Signature signP256 = (EcdsaP256Signature)signature.getSignature();
            EccP256CurvePoint pointSignP256 = signP256.getRSig();
            
            EccP256CurvePoint xonlySignP256 = null;
            if(pointSignP256.getChoice()==EccP256CurvePoint.xonly) {
                modifiedSignature = signature; // no change
            } else {
                // getEncodedPoint has x-only unimplemented
                if(pointSignP256.getChoice()==EccP256CurvePoint.uncompressedP256) {
                    Point256 point256 = (Point256) pointSignP256.getEccp256CurvePoint();
                    xonlySignP256 = EccP256CurvePoint.xOnly(point256.getX().getOctets());
                } else {
                    // does not matter y-0 or y-1, leading 0x02 or 0x03 is not included
                    xonlySignP256 = EccP256CurvePoint.xOnly(
                            ((DEROctetString) pointSignP256.getEccp256CurvePoint()).getOctets());
                }
                modifiedSignature = new Signature(signature.getChoice(), EcdsaP256Signature.builder()
                        .setRSig(xonlySignP256).setSSig(signP256.getSSig()).createEcdsaP256Signature());
            }
        } else {
            EcdsaP384Signature signP384 = (EcdsaP384Signature)signature.getSignature();
            EccP384CurvePoint pointSignP384 = signP384.getRSig();
            
            EccP384CurvePoint xonlySignP384 = null;
            if(pointSignP384.getChoice()==EccP256CurvePoint.xonly) {
                modifiedSignature = signature; // no change
            } else {
                // getEncodedPoint has x-only unimplemented
                if(pointSignP384.getChoice()==EccP384CurvePoint.uncompressedP384) {
                    Point384 point384 = (Point384) pointSignP384.getEccP384CurvePoint();
                    xonlySignP384 = EccP384CurvePoint.xOnly(point384.getX().getOctets());
                } else {
                    // does not matter y-0 or y-1, leading 0x02 or 0x03 is not included
                    xonlySignP384 = EccP384CurvePoint.xOnly(
                            ((DEROctetString) pointSignP384.getEccP384CurvePoint()).getOctets());
                }
                modifiedSignature = new Signature(signature.getChoice(), EcdsaP384Signature.builder()
                        .setRSig(xonlySignP384).setSSig(signP384.getSSig()).createEcdsaP384Signature());
            }
        }
        
        PublicVerificationKey verificationKey = (PublicVerificationKey) certificate.toASN1Structure()
                                        .getToBeSigned().getVerifyKeyIndicator().getVerificationKeyIndicator();
        PublicVerificationKey modifiedVerificationKey = null;
        if(verificationKey.getChoice()<PublicVerificationKey.ecdsaBrainpoolP384r1) {
            EccP256CurvePoint pointVKeyP256 = (EccP256CurvePoint) verificationKey.getPublicVerificationKey();
            
            EccP256CurvePoint xonlyVKeyP256 = null;
            if(pointVKeyP256.getChoice()==EccP256CurvePoint.xonly) {
                modifiedVerificationKey = verificationKey; // no change
            } else {
                // getEncodedPoint has x-only unimplemented
                if(pointVKeyP256.getChoice()==EccP256CurvePoint.uncompressedP256) {
                    Point256 point256 = (Point256) pointVKeyP256.getEccp256CurvePoint();
                    xonlyVKeyP256 = EccP256CurvePoint.xOnly(point256.getX().getOctets());
                } else {
                    // does not matter y-0 or y-1, leading 0x02 or 0x03 is not included
                    xonlyVKeyP256 = EccP256CurvePoint.xOnly(
                            ((DEROctetString) pointVKeyP256.getEccp256CurvePoint()).getOctets());
                }
                modifiedVerificationKey = new PublicVerificationKey(verificationKey.getChoice(), xonlyVKeyP256);
            }
        } else {
            EccP384CurvePoint pointVKeyP384 = (EccP384CurvePoint) verificationKey.getPublicVerificationKey();
            
            EccP384CurvePoint xonlyVKeyP384 = null;
            if(pointVKeyP384.getChoice()==EccP384CurvePoint.xonly) {
                modifiedSignature = signature; // no change
            } else {
                // getEncodedPoint has x-only unimplemented
                if(pointVKeyP384.getChoice()==EccP384CurvePoint.uncompressedP384) {
                    Point384 point384 = Point384.getInstance(pointVKeyP384.getEccP384CurvePoint());
                    xonlyVKeyP384 = EccP384CurvePoint.xOnly(point384.getX().getOctets());
                } else {
                    // does not matter y-0 or y-1, leading 0x02 or 0x03 is not included
                    xonlyVKeyP384 = EccP384CurvePoint.xOnly(
                            ((DEROctetString) pointVKeyP384.getEccP384CurvePoint()).getOctets());
                }
                modifiedVerificationKey = new PublicVerificationKey(verificationKey.getChoice(), xonlyVKeyP384);
            }
        }
        
        ToBeSignedCertificate toBeSignedCert = new ToBeSignedCertificate
                                                    .Builder(certificate.toASN1Structure().getToBeSigned())
                                                    .setVerifyKeyIndicator(
                                                       VerificationKeyIndicator.verificationKey(modifiedVerificationKey))
                                                    .createToBeSignedCertificate();
        
        CertificateBase modfiedCertificateBase =  new CertificateBase(
                            certificate.toASN1Structure().getVersion(),
                            certificate.toASN1Structure().getType(),
                            certificate.toASN1Structure().getIssuer(),
                            toBeSignedCert, modifiedSignature);
        
        return new ITSCertificate(modfiedCertificateBase);
    }
    
    public static Date getExpiryDate(ITSCertificate certificate) {
        return getExpiryDate(certificate.toASN1Structure().getToBeSigned().getValidityPeriod());
    }
    
    public static Date getExpiryDate(ValidityPeriod validityPeriod) {
        long validity = getValidityInSeconds(validityPeriod);
        long startTime = validityPeriod.getStart().toUnixMillis();
        return new Date(startTime + validity*1000);
    }
    
    public static long getValidityInSeconds(ValidityPeriod validity) {
        long result = validity.getDuration().getDuration().getValue().longValue();
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

    public static boolean verifyHashedData(byte[] marshalledAtRequest, HashedData extDataHash) {
        byte[] hashResult = null;
        if(extDataHash.getChoice()==HashedData.sha256HashedData) {
            hashResult = generateHash("SHA256", marshalledAtRequest);
        } else if(extDataHash.getChoice()==HashedData.sha384HashedData) {
            hashResult = generateHash("SHA384", marshalledAtRequest);
        } else {
            return false;
        }
        return Hex.toHexString(hashResult).equalsIgnoreCase(
                Hex.toHexString(((DEROctetString)extDataHash.getHashedData()).getOctets()));
    }
    
}
