/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.certificates;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 */
public class CrlTools extends CertificateToolsBase {

    private static final Logger log = Logger.getLogger(CrlTools.class);
    
    public static final String BEGIN_X509_CRL_KEY = "-----BEGIN X509 CRL-----";
    public static final String END_X509_CRL_KEY = "-----END X509 CRL-----";
    
    /**
     * Creates X509CRL from byte[].
     * 
     * @param crl byte array containing CRL in DER-format
     * 
     * @return X509CRL
     * 
     * @throws CRLException if the byte array does not contain a correct CRL.
     */
    public static X509CRL getCRLfromByteArray(byte[] crl) throws CRLException {
        log.trace(">getCRLfromByteArray");
        if(crl == null) {
            throw new CRLException("No content in crl byte array");
        }
        CertificateFactory cf = X509CertificateTools.getCertificateFactory(BouncyCastleProvider.PROVIDER_NAME);
        X509CRL x509crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl));
        log.trace("<getCRLfromByteArray");

        return x509crl;
    } 
    
    /**
     * Return a list of CRL distribution points. The CRL distributions points are URIs specified in the certificate extension 
     * CRLDistributionPoints with OID 2.5.29.31.
     * 
     * The CRLDistributionPoints extension contains a sequece of DistributionPoint, which has the following structure:
     * 
     *              DistributionPoint ::= SEQUENCE {
     *                   distributionPoint  [0] DistributionPointName OPTIONAL,
     *                   reasons            [1] ReasonFlags OPTIONAL,
     *                   cRLIssuer          [2] GeneralNames OPTIONAL
     *               }
     *               
     * This method extracts "distributionPoint" (tag 0) from every DistributionPoint included in the extension. No other 
     * tags are read.
     * 
     * @param x509cert
     * @return A list of URIs
     */
    public static List<String> getCrlDistributionPoints(final X509Certificate x509cert) {
        return getCrlDistributionPoints(x509cert, false);
    }

    /**
     * Extracts the URIs from a CRL Issuing Distribution Point extension of a CRL.
     * @param extensionValue Extension value of a CRL Issuing Distribution Point extension
     * @return List of URIs
     */
    public static List<String> getCrlDistributionPoints(final ASN1Primitive extensionValue) {
        return getCrlDistributionPoints(extensionValue, false);
    }
    
    /**
     * Return a list of CRL Issuing Distribution Points URIs from a CRL.
     * @see #getCrlDistributionPoints(X509Certificate)
     * @param crl CRL
     * @return A list of URIs
     */
    public static List<String> getCrlDistributionPoints(final X509CRL crl) {
        try {
            final ASN1Primitive extensionValue = getExtensionValue(crl, Extension.issuingDistributionPoint.getId());
            if (extensionValue == null) {
                return Collections.emptyList();
            }
            final IssuingDistributionPoint idp = IssuingDistributionPoint.getInstance(extensionValue);
            final DistributionPointName dpName = idp.getDistributionPoint();
            if (dpName == null || dpName.getType() != DistributionPointName.FULL_NAME) { // Relative names are not implemented
                return Collections.emptyList();
            }
            final ArrayList<String> uris = new ArrayList<>();
            final GeneralNames generalNames = GeneralNames.getInstance(dpName.getName());
            for (final GeneralName generalName : generalNames.getNames()) {
                if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    final ASN1IA5String asn1Value = ASN1IA5String.getInstance(generalName.getName());
                    uris.add(asn1Value.getString());
                }
            }
            return uris;
        } catch (IllegalArgumentException e) {
            log.debug("Malformed CRL Issuance Distribution Point", e);
            return Collections.emptyList();
        }
    }
    
    /**
     * Return the first CRL distribution points. The CRL distributions points are URL specified in the certificate extension 
     * CRLDistributionPoints with OID 2.5.29.31.
     * 
     * The CRLDistributionPoints extension contains a sequece of DistributionPoint, which has the following structure:
     * 
     *              DistributionPoint ::= SEQUENCE {
     *                   distributionPoint  [0] DistributionPointName OPTIONAL,
     *                   reasons            [1] ReasonFlags OPTIONAL,
     *                   cRLIssuer          [2] GeneralNames OPTIONAL
     *               }
     *               
     * This method extracts "distributionPoint" (tag 0) from the first DistributionPoint included in the extension. No other 
     * tags are read.
     * 
     * @param certificate
     * @return A URI, or null if no CRL distribution points were found. It is returned as a string, because it is used to
     *         identify a DP and must match exactly (no normalization allowed).
     */
    public static String getCrlDistributionPoint(final X509Certificate certificate) {
        final Collection<String> cdps = getCrlDistributionPoints(certificate, true);
        if (!cdps.isEmpty()) {
            return cdps.iterator().next();
        }
        return null;
    }
 
    
    /** @return a CRL in PEM-format as a byte array. */
    public static byte[] getPEMFromCrl(byte[] crlBytes) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try ( final PrintStream printStream = new PrintStream(baos) ) {
            X509CertificateTools.writeAsPemEncoded(printStream, crlBytes, BEGIN_X509_CRL_KEY, END_X509_CRL_KEY);
        }
        return baos.toByteArray();
    }
    
    /**
     * Get the Authority Key Identifier from CRL extensions
     * 
     * @param crl CRL containing the extension
     * @return byte[] containing the Authority key identifier, or null if it does not exist
     */
    public static byte[] getAuthorityKeyId(final X509CRL crl) {
        final ASN1Primitive asn1Sequence = X509CertificateTools.getDerObjectFromByteArray(crl.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
        if (asn1Sequence != null) {
            return AuthorityKeyIdentifier.getInstance(asn1Sequence).getKeyIdentifier();
        }
        return null;
    }
    
    /**
     * 
     * @param crl an X509CRL
     * @param oid An OID for an extension 
     * @return an Extension ASN1Primitive from a CRL
     */
    public static ASN1Primitive getExtensionValue(X509CRL crl, String oid) {
        if (crl == null || oid == null) {
            return null;
        }
        return  getDerObjectFromByteArray(crl.getExtensionValue(oid));
    }
    
    /**
     * Gets issuer DN for CRL in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param crl X509RL
     * 
     * @return String containing the DN.
     */
    public static String getIssuerDN(X509CRL crl) {
        String dn = null;
        try {
            CertificateFactory cf = X509CertificateTools.getCertificateFactory(BouncyCastleProvider.PROVIDER_NAME);
            X509CRL x509crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl.getEncoded()));
            dn = x509crl.getIssuerDN().toString();
        } catch (CRLException ce) {
            log.error("CRLException: ", ce);
            return null;
        }
        return X509CertificateTools.stringToBCDNString(dn);
    }
    
    /**
     * Generate SHA1 fingerprint of CRL in string representation.
     * 
     * @param crl X509CRL.
     * 
     * @return String containing hex format of SHA1 fingerprint.
     */
    public static String getFingerprintAsString(X509CRL crl) {
        try {
            byte[] res = generateSHA1Fingerprint(crl.getEncoded());

            return new String(Hex.encode(res));
        } catch (CRLException ce) {
            log.error("Error encoding CRL.", ce);
        }

        return null;
    }
    
    /**
     * This utility method extracts the Authority Information Access Extention's URLs
     * 
     * @param crl a CRL to parse
     * @return the Authority Information Access Extention's URLs, or an empty Collection if none were found
     */
    public static Collection<String> getAuthorityInformationAccess(CRL crl) {
        Collection<String> result = new ArrayList<>();
        if (crl instanceof X509CRL) {
            X509CRL x509crl = (X509CRL) crl;
            ASN1Primitive derObject = getExtensionValue(x509crl, Extension.authorityInfoAccess.getId());
            if (derObject != null) {
                AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(derObject);
                AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
                if ((accessDescriptions != null) && (accessDescriptions.length > 0)) {
                    for (AccessDescription accessDescription : accessDescriptions) {
                        if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                            GeneralName generalName = accessDescription.getAccessLocation();
                            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                // Due to bug in java getting some ASN.1 objects, it can be tagged an extra time...
                                ASN1Primitive obj = generalName.toASN1Primitive();
                                if (obj instanceof ASN1TaggedObject) {
                                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                                }
                                final ASN1IA5String deria5String = ASN1IA5String.getInstance(obj);
                                result.add(deria5String.getString());
                            }
                        }
                    }
                }
            }
        }
        return result;
    }
    
    private static List<String> getCrlDistributionPoints(final X509Certificate x509cert, final boolean onlyfirst) {
        final ASN1Primitive extensionValue = X509CertificateTools.getExtensionValue(x509cert, Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return Collections.emptyList();
        }
        return getCrlDistributionPoints(extensionValue, onlyfirst);
    }
    
    private static List<String> getCrlDistributionPoints(final ASN1Primitive extensionValue, final boolean onlyfirst) {
        final ArrayList<String> cdps = new ArrayList<>();
        final ASN1Sequence crlDistributionPoints = ASN1Sequence.getInstance(extensionValue);
        for (int i = 0; i < crlDistributionPoints.size(); i++) {
            final ASN1Sequence distributionPoint = ASN1Sequence.getInstance(crlDistributionPoints.getObjectAt(i));
            for (int j = 0; j < distributionPoint.size(); j++) {
                final ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(distributionPoint.getObjectAt(j));
                if (tagged.getTagNo() == 0) {
                    String url = getStringFromGeneralNames(tagged.getObject());
                    if(url!=null) {
                        try {
                            new URL(url); // Syntax check
                            cdps.add(url);
                        } catch (MalformedURLException e) {
                            if(log.isDebugEnabled()) {
                                log.debug("Error parsing '" + url + "' as a URL. " + e.getLocalizedMessage());
                            }
                        }
                    }
                    if(onlyfirst) {
                        return cdps; // returning only the first URL
                    }
                }
            }
        }
        return cdps;
    }
    
    /**
     * Gets a URI string from a GeneralNames structure.
     * 
     * @param names DER GeneralNames object, that is a sequence of DERTaggedObject
     * @return String with URI if tagNo is 6 (uniformResourceIdentifier), null otherwise
     */
    private static String getStringFromGeneralNames(ASN1Primitive names) {
        final ASN1Sequence namesSequence = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(names), false);
        if (namesSequence.size() == 0) {
            return null;
        }
        final ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(namesSequence.getObjectAt(0));
        if (taggedObject.getTagNo() != GeneralName.uniformResourceIdentifier) { // uniformResourceIdentifier [6] IA5String,
            return null;
        }
        return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets());
    }

}
