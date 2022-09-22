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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.CharUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralString;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.util.Base64;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.RFC4683Tools;
import org.cesecore.util.SecurityFilterInputStream;
import org.cesecore.util.StringTools;

import com.novell.ldap.LDAPDN;


/**
 *
 */
public class X509CertificateTools extends CertificateToolsBase {

    private static final Logger log = Logger.getLogger(X509CertificateTools.class);
    
    public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    public static final String BEGIN_CERTIFICATE_WITH_NL = "-----BEGIN CERTIFICATE-----\n";
    public static final String END_CERTIFICATE_WITH_NL = "\n-----END CERTIFICATE-----\n";
    public static final String BEGIN_CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String END_CERTIFICATE_REQUEST = "-----END CERTIFICATE REQUEST-----";
    
    public static final String EMAIL = "rfc822name";
    public static final String EMAIL1 = "email";
    public static final String EMAIL2 = "EmailAddress";
    public static final String EMAIL3 = "E";
    public static final String DNS = "dNSName";
    public static final String URI = "uniformResourceIdentifier";
    public static final String URI1 = "uri";
    public static final String URI2 = "uniformResourceId";
    public static final String IPADDR = "iPAddress";
    public static final String DIRECTORYNAME = "directoryName";
    public static final String REGISTEREDID = "registeredID";
    public static final String XMPPADDR = "xmppAddr";
    public static final String SRVNAME = "srvName";
    public static final String FASCN = "fascN";
    
    /** Microsoft altName for windows smart card logon */
    public static final String UPN = "upn";
    /** ObjectID for upn altName for windows smart card logon */
    public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
    public static final String PERMANENTIDENTIFIER = "permanentIdentifier";
    public static final String PERMANENTIDENTIFIER_OBJECTID = "1.3.6.1.5.5.7.8.3";
    /** Kerberos altName for smart card logon */
    public static final String KRB5PRINCIPAL = "krb5principal";
    /** OID for Kerberos altName for smart card logon */
    public static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";
    /** ObjectID for srvName, rfc4985 */
    public static final String SRVNAME_OBJECTID =  "1.3.6.1.5.5.7.8.7";
    public static final String FASCN_OBJECTID =  "2.16.840.1.101.3.6.6";
    /** Microsoft altName for windows domain controller guid */
    public static final String GUID = "guid";
    /** ObjectID for upn altName for windows domain controller guid */
    public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
    /** ObjectID for XmppAddr, rfc6120#section-13.7.1.4 */
    public static final String XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
    
    private  static final String PERMANENTIDENTIFIER_SEP = "/";
    
    private static final String[] EMAILIDS = { EMAIL, EMAIL1, EMAIL2, EMAIL3 };
    
    private static final Pattern UNESCAPE_FIELD_REGEX = Pattern.compile("\\\\([,+\"\\\\<>; ])");
    
    
    
    /**
     * class for breaking up an X500 Name into it's component tokens, ala java.util.StringTokenizer. 
     */
    private static class X509NameTokenizer {
        private String value;
        private int index;
        private char separator;
        private StringBuffer buf = new StringBuffer();

        /** Creates the object, using the default comma (,) as separator for tokenization */
        public X509NameTokenizer(String oid) {
            this(oid, ',');
        }

        public X509NameTokenizer(String oid, char separator) {
            this.value = oid;
            this.index = -1;
            this.separator = separator;
        }

        public boolean hasMoreTokens() {
            return (value != null && index != value.length());
        }

        public String nextToken() {
            if (index == value.length()) {
                return null;
            }

            int end = index + 1;
            boolean quoted = false;
            boolean escaped = false;

            buf.setLength(0);

            while (end != value.length()) {
                char c = value.charAt(end);

                if (c == '"') {
                    if (!escaped) {
                        quoted = !quoted;
                    } else {
                        if (c == '#' && buf.charAt(buf.length() - 1) == '=') {
                            buf.append('\\');
                        } else if (c == '+' && separator != '+') {
                            buf.append('\\');
                        }
                        buf.append(c);
                    }
                    escaped = false;
                } else {
                    if (escaped || quoted) {
                        if (c == '#' && buf.charAt(buf.length() - 1) == '=') {
                            buf.append('\\');
                        } else if (c == '+' && separator != '+') {
                            buf.append('\\');
                        }
                        buf.append(c);
                        escaped = false;
                    } else if (c == '\\') {
                        escaped = true;
                    } else if (c == separator) {
                        break;
                    } else {
                        buf.append(c);
                    }
                }
                end++;
            }

            index = end;
            return buf.toString().trim();
        }

        /**
         * Returns the remaining (not yet tokenized) part of the DN.
         */
        String getRemainingString() {
            return index + 1 < value.length() ? value.substring(index + 1) : "";
        }
    }
    
    /**
     * class for breaking up an X500 Name into it's component tokens, ala java.util.StringTokenizer. Taken from BouncyCastle, but does NOT use or
     * consider escaped characters. Used for reversing DNs without unescaping.
     */
    private static class BasicX509NameTokenizer {
        final private String oid;
        private int index = -1;
        /* 
         * Since this class isn't thread safe anyway, we can use the slightly faster StringBuilder instead of StringBuffer 
         */
        private StringBuilder buf = new StringBuilder();

        public BasicX509NameTokenizer(String oid) {
            this.oid = oid;
        }

        public boolean hasMoreTokens() {
            return (index != oid.length());
        }

        public String nextToken() {
            if (index == oid.length()) {
                return null;
            }

            int end = index + 1;
            boolean quoted = false;
            boolean escaped = false;

            buf.setLength(0);

            while (end != oid.length()) {
                char c = oid.charAt(end);

                if (c == '"') {
                    if (!escaped) {
                        buf.append(c);
                        quoted ^= true; // Faster than "quoted = !quoted;"
                    } else {
                        buf.append(c);
                    }
                    escaped = false;
                } else {
                    if (escaped || quoted) {
                        buf.append(c);
                        escaped = false;
                    } else if (c == '\\') {
                        buf.append(c);
                        escaped = true;
                    } else if ((c == ',') && (!escaped)) {
                        break;
                    } else {
                        buf.append(c);
                    }
                }
                end++;
            }

            index = end;
            return buf.toString().trim();
        }
    } // BasicX509NameTokenizer

    
    /**
     * Reads certificates in PEM-format from a filename.
     * The stream may contain other things between the different certificates.
     * 
     * @param certFilename filename of the file containing the certificates in PEM-format
     * @return Ordered List of Certificates, first certificate first, or empty List
     * @throws FileNotFoundException if certFile was not found
     * @throws CertificateParsingException if the file contains an incorrect certificate.
     * 
     */
    public static List<X509Certificate> getCertsFromPEM(String certFilename) throws FileNotFoundException, CertificateParsingException {
        if (log.isTraceEnabled()) {
            log.trace(">getCertfromPEM: certFilename=" + certFilename);
        }
        final List<X509Certificate> certs;
        try (final InputStream inStrm = new FileInputStream(certFilename)) {
            certs = getCertsFromPEM(inStrm);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to close input stream");
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertfromPEM: certFile=" + certFilename);
        }
        return certs;
     }
    
    /**
     * Checks that the given date is within the certificate's validity period. In other words, this determines whether the certificate would be valid
     * at the given date/time.
     * 
     * 
     * @param cert certificate to verify, if null the method returns immediately, null does not have a validity to check.
     * @param date the Date to check against to see if this certificate is valid at that date/time.
     * @throws NoSuchFieldException
     * @throws CertificateExpiredException - if the certificate has expired with respect to the date supplied.
     * @throws CertificateNotYetValidException - if the certificate is not yet valid with respect to the date supplied.
     * @see java.security.cert.X509Certificate#checkValidity(Date)
     */
    public static void checkValidity(final X509Certificate xcert, final Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        if (xcert != null) {
            xcert.checkValidity(date);
        }
    }
    
    /**
     * Converts a X509Certificate chain into a JcaX509CertificateHolder chain.
     * 
     * @param certificateChain input chain to be converted
     * @return the result
     * @throws CertificateEncodingException if there is a problem extracting the certificate information.
     */
    public static final JcaX509CertificateHolder[] convertToX509CertificateHolder(X509Certificate[] certificateChain)
            throws CertificateEncodingException {
        final JcaX509CertificateHolder[] certificateHolderChain = new JcaX509CertificateHolder[certificateChain.length];
        for (int i = 0; i < certificateChain.length; ++i) {
            certificateHolderChain[i] = new JcaX509CertificateHolder(certificateChain[i]);
        }
        return certificateHolderChain;
    }
    
    /**
     * Converts a X509Certificate chain into a JcaX509CertificateHolder chain.
     * 
     * @param certificateChain input chain to be converted
     * @return the result
     * @throws CertificateEncodingException if there is a problem extracting the certificate information.
     */
    public static final List<JcaX509CertificateHolder> convertToX509CertificateHolder(List<X509Certificate> certificateChain)
            throws CertificateEncodingException {
        final List<JcaX509CertificateHolder> certificateHolderChain = new ArrayList<>();
        for (X509Certificate certificate : certificateChain) {
            certificateHolderChain.add( new JcaX509CertificateHolder(certificate));
        }
        return certificateHolderChain;
    }
    
    /**
     * Converts a X509CertificateHolder chain into a X509Certificate chain.
     * 
     * @param certificateHolderChain input chain to be converted
     * @return the result
     * @throws CertificateException if there is a problem extracting the certificate information.
     */
    public static final List<X509Certificate> convertToX509CertificateList(Collection<X509CertificateHolder> certificateHolderChain) throws CertificateException {
        final List<X509Certificate> ret = new ArrayList<>();
        final JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        for (final X509CertificateHolder certificateHolder : certificateHolderChain) {
            ret.add(jcaX509CertificateConverter.getCertificate(certificateHolder));
        }
        return ret;
    }
    
    /**
     * Create a "certs-only" PKCS#7 / CMS from the provided chain.
     * 
     * @param x509CertificateChain chain of certificates with the leaf in the first position and root in the last or just a leaf certificate.
     * @return a byte array containing the CMS
     * @throws CertificateEncodingException if the provided list of certificates could not be parsed correctly
     * @throws CMSException if there was a problem creating the certs-only CMS message
     */
    public static byte[] createCertsOnlyCMS(final List<X509Certificate> x509CertificateChain) throws CertificateEncodingException, CMSException {
        if (log.isDebugEnabled()) {
            final String subjectdn = ( (x509CertificateChain != null && !x509CertificateChain.isEmpty()) ? x509CertificateChain.get(0).getSubjectDN().toString() : "null");  
            log.debug("Creating a certs-only CMS for " + subjectdn);
        }
        final List<JcaX509CertificateHolder> certList = convertToX509CertificateHolder(x509CertificateChain);
        final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        cmsSignedDataGenerator.addCertificates(new CollectionStore<>(certList));
        final CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(new CMSAbsentContent(), true);
        try {
            return cmsSignedData.getEncoded();
        } catch (IOException e) {
            throw new CMSException(e.getMessage());
        }
    }
    
    /**
     * @return all CA issuer URI that are inside AuthorityInformationAccess extension or an empty list
     */
    public static List<String> getAuthorityInformationAccessCAIssuerUris(final X509Certificate x509cert) {
        final List<String> urls = new ArrayList<>();
        final ASN1Primitive obj = getExtensionValue(x509cert, Extension.authorityInfoAccess.getId());
        if (obj != null) {
            final AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(obj).getAccessDescriptions();
            if (accessDescriptions != null) {
                for (final AccessDescription accessDescription : accessDescriptions) {
                    // OID 1.3.6.1.5.5.7.48.2: 2 times in Bouncy Castle X509ObjectIdentifiers class.
                    // X509ObjectIdentifiers.id_ad_caIssuers = X509ObjectIdentifiers.crlAccessMethod
                    if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                        final GeneralName generalName = accessDescription.getAccessLocation();
                        if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            // After encoding in a cert, it is tagged an extra time...
                            ASN1Primitive gnobj = generalName.toASN1Primitive();
                            if (gnobj instanceof ASN1TaggedObject) {
                                gnobj = ASN1TaggedObject.getInstance(gnobj).getObject();
                            }
                            final ASN1IA5String str = ASN1IA5String.getInstance(gnobj);
                            if (str != null) {
                                urls.add(str.getString());
                            }
                        }
                    }
                }
            }

        }
        return urls;
    }
    
    /**
     * Returns the first OCSP URL that is inside AuthorityInformationAccess extension, or null.
     * 
     * @param cert is the certificate to parse
     */
    public static String getAuthorityInformationAccessOcspUrl(X509Certificate cert) {
        Collection<String> urls = getAuthorityInformationAccessOcspUrls(cert);
        if(!urls.isEmpty()) {
            return urls.iterator().next();
        }
        return null;
    }
    
    /**
     * @return all OCSP URL that is inside AuthorityInformationAccess extension or an empty list
     */
    public static List<String> getAuthorityInformationAccessOcspUrls(X509Certificate cert) {
        return getAuthorityInformationAccessOcspUrls(cert, false);
    }
    
    /**
     * @return all OCSP URL that is inside AuthorityInformationAccess extension or an empty list
     */
    private static List<String> getAuthorityInformationAccessOcspUrls(X509Certificate x509cert, final boolean onlyfirst) {
        final List<String> urls = new ArrayList<>();
        final ASN1Primitive obj = getExtensionValue(x509cert, Extension.authorityInfoAccess.getId());
        if (obj != null) {
            final AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(obj).getAccessDescriptions();
            if (accessDescriptions != null) {
                for (final AccessDescription accessDescription : accessDescriptions) {
                    // OID 1.3.6.1.5.5.7.48.1: 2 times in Bouncy Castle X509ObjectIdentifiers class.
                    // X509ObjectIdentifiers.id_ad_ocsp = X509ObjectIdentifiers.ocspAccessMethod
                    if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod)) {
                        final GeneralName generalName = accessDescription.getAccessLocation();
                        if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            // After encoding in a cert, it is tagged an extra time...
                            ASN1Primitive gnobj = generalName.toASN1Primitive();
                            if (gnobj instanceof ASN1TaggedObject) {
                                gnobj = ASN1TaggedObject.getInstance(gnobj).getObject();
                            }
                            final ASN1IA5String str = ASN1IA5String.getInstance(gnobj);
                            if (str != null) {
                                urls.add(str.getString());
                            }
                            if (onlyfirst) {
                                return urls; // returning only the first URL
                            }
                        }
                    }
                }
            }
        }

        return urls;
    }
    
    /**
     * Is OCSP extended key usage set for a certificate?
     * 
     * @param cert to check.
     * @return true if the extended key usage for OCSP is check
     */
    public static boolean isOCSPCert(X509Certificate cert) {
        final List<String> keyUsages;
        try {
            keyUsages = cert.getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            return false;
        }
        return keyUsages != null && keyUsages.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
    }
    
    /**
     * Check the certificate with CA certificate.
     * 
     * @param certificate X.509 certificate to verify. May not be null.
     * @param caCertChain Collection of X509Certificates. May not be null, an empty list or a Collection with null entries.
     * @return true if verified OK
     * @throws CertPathValidatorException if verification failed
     */
    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain) throws CertPathValidatorException {
        return verify(certificate, caCertChain, null);
    }
    
    /**
     * Check the certificate with a list of trusted certificates.
     * The trusted certificates list can either be end entity certificates, in this case, only this certificate by this issuer 
     * is trusted; or it could be CA certificates, in this case, all certificates issued by this CA are trusted.
     * 
     * @param certificate certificate to verify
     * @param trustedCertificates collection of trusted X509Certificates, empty list trust everything, null trusts nothing.
     * @param pkixCertPathCheckers optional PKIXCertPathChecker implementations to use during cert path validation
     * @return true if verified OK
     */
    public static boolean verifyWithTrustedCertificates(X509Certificate certificate, List< Collection<X509Certificate>> trustedCertificates, PKIXCertPathChecker...pkixCertPathCheckers) {
        
        if(trustedCertificates == null) {
            if(log.isDebugEnabled()) {
                log.debug("Input of trustedCertificates was null. Trusting nothing.");
            }
            return false;
        }
        
        if (trustedCertificates.isEmpty()) {
            if(log.isDebugEnabled()) {
                log.debug("Input of trustedCertificates was empty. Trusting everything.");
            }
            return true;
        }
        
        BigInteger certSN = getSerialNumber(certificate);
        for(Collection<X509Certificate> trustedCertChain : trustedCertificates) {
            X509Certificate trustedCert = trustedCertChain.iterator().next();
            BigInteger trustedCertSN = getSerialNumber(trustedCert);
            if(certSN.equals(trustedCertSN)) {
                // If the serial number of the certificate matches the serial number of a certificate in the list, make sure that it in 
                // fact is the same certificate by verifying that they were issued by the same issuer.
                // Removing this trusted certificate from the trustedCertChain will leave only the CA's certificate chain, which will be 
                // used to verify the issuer.
                if(trustedCertChain.size() > 1) {
                    trustedCertChain.remove(trustedCert);
                }
            }
            try {
                verify(certificate, trustedCertChain, null, pkixCertPathCheckers);
                if(log.isDebugEnabled()) {
                    log.debug("Trusting certificate with SubjectDN '" + getSubjectDN(certificate) + "' and issuerDN '" + getIssuerDN(certificate) + "'.");
                }
                return true;
            } catch (CertPathValidatorException e) {
                //Do nothing. Just try the next trusted certificate chain in the list
            }
            
        }
        return false;
    }
    
    /**
     * Check the certificate with CA certificate.
     * 
     * @param certificate X.509 certificate to verify. May not be null.
     * @param caCertChain Collection of X509Certificates. May not be null, an empty list or a Collection with null entries.
     * @param date Date to verify at, or null to use current time.
     * @param pkixCertPathCheckers optional PKIXCertPathChecker implementations to use during cert path validation
     * @return true if verified OK
     * @throws CertPathValidatorException if certificate could not be validated
     */
    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain, Date date, PKIXCertPathChecker... pkixCertPathCheckers)
            throws CertPathValidatorException {
        if (caCertChain == null || caCertChain.isEmpty()) {
            throw new CertPathValidatorException("Chain is missing.");
        }
        try {
            List<X509Certificate> certlist = new ArrayList<>();
            // Create CertPath
            certlist.add(certificate);
            // Add other certs...
            CertPath cp = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME).generateCertPath(certlist);        
            // Create TrustAnchor. Since EJBCA use BouncyCastle provider, we assume
            // certificate already in correct order
            X509Certificate[] cac = caCertChain.toArray(new X509Certificate[caCertChain.size()]);
            TrustAnchor anchor = new TrustAnchor(cac[0], null);
            // Set the PKIX parameters
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            for (final PKIXCertPathChecker pkixCertPathChecker : pkixCertPathCheckers) {
                params.addCertPathChecker(pkixCertPathChecker);
            }
            params.setRevocationEnabled(false);
            params.setDate(date);
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
            if (log.isDebugEnabled()) {
                log.debug("Certificate verify result: " + result.toString());
            }
        } catch (CertPathValidatorException cpve) {
            throw new CertPathValidatorException("Invalid certificate or certificate not issued by specified CA: " + cpve.getMessage());
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Something was wrong with the supplied certificate", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider not found.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm PKIX was not found.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("Either ca certificate chain was empty, or the certificate was on an inappropraite type for a PKIX path checker.", e);
        }
        return true;
    }

    
    /**
     * Returns a certificate in PEM-format.
     * 
     * @param certs Collection of Certificate to convert to PEM
     * @return byte array containing PEM certificate
     * @throws CertificateEncodingException if an encoding error occurred
     */
    public static byte[] getPemFromCertificateChain(Collection<Certificate> certs) throws CertificateEncodingException  {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try ( final PrintStream printStream = new PrintStream(baos) ) {
            for (final Certificate certificate : certs) {
                if (certificate != null) {
                    printStream.println("Subject: " + getDN(certificate, 1));
                    printStream.println("Issuer: " +  getDN(certificate, 2));
                    writeAsPemEncoded(printStream, certificate.getEncoded(), BEGIN_CERTIFICATE, END_CERTIFICATE);                    
                }
            }
        }
        return baos.toByteArray();
    }
    
    /**
     * Reads certificates in PEM-format from an InputStream. 
     * The stream may contain other things between the different certificates.
     * 
     * @param certstream the input stream containing the certificates in PEM-format
     * @return Ordered List of Certificates, first certificate first, or empty List
     * @exception CertificateParsingException if the stream contains an incorrect certificate.
     */
    public static List<X509Certificate> getCertsFromPEM(final InputStream certstream) throws CertificateParsingException {
        if (log.isTraceEnabled()) {
            log.trace(">getCertfromPEM");
        }
        final List<X509Certificate> ret = new ArrayList<>();
        String beginKeyTrust = "-----BEGIN TRUSTED CERTIFICATE-----";
        String endKeyTrust = "-----END TRUSTED CERTIFICATE-----";
        try (final BufferedReader bufRdr = new BufferedReader(new InputStreamReader(new SecurityFilterInputStream(certstream)))) {
            while (bufRdr.ready()) {
                final ByteArrayOutputStream ostr = new ByteArrayOutputStream();
                final PrintStream opstr = new PrintStream(ostr);
                String temp;
                while ((temp = bufRdr.readLine()) != null && !(temp.equals(BEGIN_CERTIFICATE) || temp.equals(beginKeyTrust))) {
                    continue;
                }
                if (temp == null) {
                    if (ret.isEmpty()) {
                        // There was no certificate in the file
                        throw new CertificateParsingException("Error in " + certstream.toString() + ", missing " + BEGIN_CERTIFICATE
                                + " boundary");
                    } else {
                        // There were certificates, but some blank lines or something in the end
                        // anyhow, the file has ended so we can break here.
                        break;
                    }
                }
                while ((temp = bufRdr.readLine()) != null && !(temp.equals(END_CERTIFICATE) || temp.equals(endKeyTrust))) {
                    opstr.print(temp);
                }
                if (temp == null) {
                    throw new IllegalArgumentException("Error in " + certstream.toString() + ", missing " + END_CERTIFICATE
                            + " boundary");
                }
                opstr.close();

                byte[] certbuf = Base64.decode(ostr.toByteArray());
                ostr.close();
                // Phweeew, were done, now decode the cert from file back to Certificate object
                X509Certificate cert = parseCertificate(BouncyCastleProvider.PROVIDER_NAME, certbuf);
                ret.add(cert);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Exception caught when attempting to read stream, see underlying IOException", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<getcertfromPEM:" + ret.size());
        }
        return ret;
    }

    /**
     * Method used to insert a CN postfix into DN by extracting the first found CN appending cnpostfix and then replacing the original CN with the new
     * one in DN.
     * 
     * If no CN could be found in DN then should the given DN be returned untouched
     * 
     * @param dn the DN to manipulate, cannot be null
     * @param cnpostfix the postfix to insert, cannot be null
     * @param nameStyle Controls how the name is encoded. Usually it should be a CeSecoreNameStyle.
     * @return the new DN
     */
    public static String insertCNPostfix(String dn, String cnpostfix, X500NameStyle nameStyle) {
        if (log.isTraceEnabled()) {
            log.trace(">insertCNPostfix: dn=" + dn + ", cnpostfix=" + cnpostfix);
        }
        if (dn == null) {
            return null;
        }
        final RDN[] rdns = IETFUtils.rDNsFromString(dn, nameStyle);
        final X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
        boolean replaced = false;
        for (final RDN rdn : rdns) {
            final AttributeTypeAndValue[] attributeTypeAndValues = rdn.getTypesAndValues();
            for (final AttributeTypeAndValue atav : attributeTypeAndValues) {
                if (atav.getType() != null) {
                    final String currentSymbol = CeSecoreNameStyle.DefaultSymbols.get(atav.getType());
                    if (!replaced && "CN".equals(currentSymbol)) {
                        nameBuilder.addRDN(atav.getType(), IETFUtils.valueToString(atav.getValue()) + cnpostfix);
                        replaced = true;
                    } else {
                        nameBuilder.addRDN(atav);
                    }
                }
            }
        }
        final String ret = nameBuilder.build().toString();
        if (log.isTraceEnabled()) {
            log.trace("<reverseDN: " + ret);
        }
        return ret;
    }
    
    /**
     * 
     * @param provider a provider name 
     * @param cert a byte array containing an encoded certificate
     * @return a decoded X509Certificate
     * @throws CertificateParsingException if the byte array wasn't valid, or contained a certificate other than an X509 Certificate. 
     */
    public static X509Certificate parseCertificate(String provider, byte[] cert) throws CertificateParsingException {
        final CertificateFactory cf = getCertificateFactory(provider);
        X509Certificate result;
        try {
           result = (X509Certificate) cf.generateCertificate(new SecurityFilterInputStream(new ByteArrayInputStream(cert)));      
        } catch (CertificateException e) {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate." + e.getCause().getMessage(), e);
        }
        if(result != null) {
            return result;
        } else {
            throw new CertificateParsingException("Could not parse byte array as X509Certificate.");
        }
    }
    
    /**
     * 
     * @param cert An X509Certificate
     * @param oid An OID for an extension 
     * @return an Extension ASN1Primitive from a certificate, or null
     */
    public static ASN1Primitive getExtensionValue(X509Certificate cert, String oid) {
        if (cert == null) {
            return null;
        }
        return getDerObjectFromByteArray(cert.getExtensionValue(oid));
    }
    
    /**
     * Every DN-string should look the same. Creates a name string ordered and looking like we want it...
     * 
     * @param dn String containing DN
     * 
     * @return String containing DN, or empty string if dn does not contain any real DN components, or null if input is null
     */
    public static String stringToBCDNString(String dn) {
        // BC now seem to handle multi-valued RDNs, but we keep escaping this for now to keep the behavior until support is required
        //dn = handleUnescapedPlus(dn); // Log warning if dn contains unescaped '+'
        if (isDNReversed(dn)) {
            dn = reverseDN(dn);
        }
        String ret = null;
        final X500Name name = stringToBcX500Name(dn);
        if (name != null) {
            ret = name.toString();
        }
        /*
         * For some databases (MySQL for instance) the database column holding subjectDN is only 250 chars long. There have been strange error
         * reported (clipping DN naturally) that is hard to debug if DN is more than 250 chars and we don't have a good message
         */
        if ((ret != null) && (ret.length() > 250)) {
            log.info("Warning! DN is more than 250 characters long. Some databases have only 250 characters in the database for SubjectDN. Clipping may occur! DN ("
                    + ret.length() + " chars): " + ret);
        }
        return ret;
    }
    
    /**
     * Tries to determine if a DN is in reversed form. It does this by taking the last attribute and the first attribute. If the last attribute comes
     * before the first in the dNObjects array the DN is assumed to be in reversed order.
     * 
     * The default ordering is: "CN=Tomas, O=PrimeKey, C=SE" (dNObjectsForward ordering in EJBCA) a dn or form "C=SE, O=PrimeKey, CN=Tomas" is
     * reversed.
     * 
     * If the string has only one component (e.g. "CN=example.com") then this method returns false.
     * If the string does not contain any real DN components, it returns false. 
     * 
     * @param dn String containing DN to be checked, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @return true if the DN is believed to be in reversed order, false otherwise
     */
    public static boolean isDNReversed(String dn) {
        boolean ret = false;
        if (dn != null) {
            String first = null;
            String last = null;
            X509NameTokenizer xt = new X509NameTokenizer(dn);
            if (xt.hasMoreTokens()) {
                first = xt.nextToken().trim();
            }
            while (xt.hasMoreTokens()) {
                last = xt.nextToken().trim();
            }
            String[] dNObjects = DnComponents.getDnObjects(true);
            if ((first != null) && (last != null)) {
                // Be careful for bad input, that may not have any = sign in it
                final int fi = first.indexOf('=');
                first = first.substring(0, (fi != -1 ? fi : (first.length()-1)));
                final int li = last.indexOf('=');
                last = last.substring(0, (li != -1 ? li : (last.length()-1)));
                int firsti = 0, lasti = 0;
                for (int i = 0; i < dNObjects.length; i++) {
                    if (first.equalsIgnoreCase(dNObjects[i])) {
                        firsti = i;
                    }
                    if (last.equalsIgnoreCase(dNObjects[i])) {
                        lasti = i;
                    }
                }
                if (lasti < firsti) {
                    ret = true;
                }

            }
        }
        return ret;
    } 
    
    /**
     * Takes a DN and reverses it completely so the first attribute ends up last. C=SE,O=Foo,CN=Bar becomes CN=Bar,O=Foo,C=SE.
     * 
     * @param dn String containing DN to be reversed, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * 
     * @return String containing reversed DN
     */
    public static String reverseDN(String dn) {
        if (log.isTraceEnabled()) {
            log.trace(">reverseDN: dn: " + dn);
        }
        String ret = null;
        if (dn != null) {
            String o;
            final BasicX509NameTokenizer xt = new BasicX509NameTokenizer(dn);
            StringBuilder buf = new StringBuilder();
            boolean first = true;
            while (xt.hasMoreTokens()) {
                o = xt.nextToken();
                // log.debug("token: "+o);
                if (!first) {
                    buf.insert(0, ",");
                } else {
                    first = false;
                }
                buf.insert(0, o);
            }
            if (buf.length() > 0) {
                ret = buf.toString();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<reverseDN: resulting dn: " + ret);
        }
        return ret;
    }
    
    /**
     * See stringToBcX500Name(String, X500NameStyle, boolean), this method uses the default name style (CeSecoreNameStyle) and ldap
     * order
     * 
     * @see #stringToBcX500Name(String, X500NameStyle, boolean)
     * @param dn String containing DN that will be transformed into X500Name, The DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
     *            the string will be added to the end positions of OID array.
     * 
     * @return X500Name, which can be empty if dn does not contain any real DN components, or null if input is null
     */
    public static X500Name stringToBcX500Name(final String dn) {
        final X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
        return stringToBcX500Name(dn, nameStyle, true);
    }
    
    /**
     * See stringToBcX500Name(String, X500NameStyle, boolean), this method uses the default name style (CeSecoreNameStyle) and ldap
     * order
     * 
     * @see #stringToBcX500Name(String, X500NameStyle, boolean)
     * @param dn String containing DN that will be transformed into X500Name, The DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
     *            the string will be added to the end positions of OID array.
     * @param ldapOrder true if X500Name should be in Ldap Order
     * @return X500Name, which can be empty if dn does not contain any real DN components, or null if input is null
     */
    public static X500Name stringToBcX500Name(final String dn, boolean ldapOrder) {
        final X500NameStyle nameStyle = CeSecoreNameStyle.INSTANCE;
        return stringToBcX500Name(dn, nameStyle, ldapOrder);
    }
    
    /**
     * Creates a (Bouncycastle) X500Name object from a string with a DN. Known OID (with order) are:
     * <code> EmailAddress, UID, CN, SN (SerialNumber), GivenName, Initials, SurName, T, OU,
     * O, L, ST, DC, C </code> To change order edit 'dnObjects' in this source file. Important NOT to mess with the ordering within this class, since
     * cert vierification on some clients (IE :-() might depend on order.
     * 
     * @param dn String containing DN that will be transformed into X500Name, The DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
     *            the string will be added to the end positions of OID array.
     * @param nameStyle Controls how the name is encoded. Usually it should be a CeSecoreNameStyle.
     * @param ldaporder true if LDAP ordering of DN should be used (default in EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
     *            order is the reverse
     * @return X500Name, which can be empty if dn does not contain any real DN components, or null if input is null
     * @throws IllegalArgumentException if DN is not valid
     */
    public static X500Name stringToBcX500Name(String dn, final X500NameStyle nameStyle, final boolean ldaporder) {
        return stringToBcX500Name(dn, nameStyle, ldaporder, null);
    }
    
    /** Same as @see {@link CertTools#stringToBcX500Name(String, X500NameStyle, boolean)} but with the possibility of 
     * specifying a custom order. 
     * ONLY to be used when creating names that are transient, never for storing in the database.
     * 
     * @param dn String containing DN that will be transformed into X500Name, The DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
     *            the string will be added to the end positions of OID array.
     * @param nameStyle Controls how the name is encoded. Usually it should be a CeSecoreNameStyle.
     * @param ldaporder true if LDAP ordering of DN should be used (default in EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
     *            order is the reverse
     * @param order specified order, which overrides 'ldaporder', care must be taken constructing this String array, ignored if null or empty
     * @return X500Name, which can be empty if dn does not contain any real DN components, or null if input is null
     * @throws IllegalArgumentException if the DN is badly formatted 
     */
    public static X500Name stringToBcX500Name(String dn, final X500NameStyle nameStyle, final boolean ldaporder, final String[] order) {
        return stringToBcX500Name(dn, nameStyle, ldaporder, order, true);
    }
    
    public static X500Name stringToBcX500Name(String dn, final X500NameStyle nameStyle, final boolean ldaporder, final String[] order, final boolean applyLdapToCustomOrder) {
        final X500Name x500Name = stringToUnorderedX500Name(dn, nameStyle);
        if (x500Name==null) {
            return null;
        }
        // -- Reorder fields
        final X500Name orderedX500Name = getOrderedX500Name(x500Name, ldaporder, order, applyLdapToCustomOrder, nameStyle);
        if (log.isTraceEnabled()) {
            log.trace(">stringToBcX500Name: x500Name=" + x500Name.toString() + " orderedX500Name=" + orderedX500Name.toString());
        }
        return orderedX500Name;
    }

    /**
     * Gets a list of all custom OIDs defined in the string. A custom OID is defined as an OID, simply as that. Otherwise, if it is not a custom oid,
     * the DNpart is defined by a name such as CN och rfc822Name. This method only returns a oid once, so if the input string has multiple of the same
     * oid, only one value is returned.
     * 
     * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz", or "rfc822Name=foo@bar.com", etc.
     * @param dn String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * 
     * @return ArrayList containing unique oids or empty list if no custom OIDs are present
     */
    public static List<String> getCustomOids(String dn) {
        if (log.isTraceEnabled()) {
            log.trace(">getCustomOids: dn:'" + dn);
        }
        List<String> parts = new ArrayList<>();
        if (dn != null) {
            String o;
            X509NameTokenizer xt = new X509NameTokenizer(dn);
            while (xt.hasMoreTokens()) {
                o = xt.nextToken().trim();
                // Try to see if it is a valid OID
                try {
                    int i = o.indexOf('=');
                    // An oid is never shorter than 3 chars and must start with 1.
                    if ((i > 2) && (o.charAt(1) == '.')) {
                        String oid = o.substring(0, i);
                        // If we have multiple of the same custom oid, don't claim that we have more
                        // This method will only return "unique" custom oids.
                        if (!parts.contains(oid)) {
                            // Check if it is a real oid, if it is not we will ignore it (IllegalArgumentException will be thrown)
                            new ASN1ObjectIdentifier(oid);
                            parts.add(oid);
                        }
                    }
                } catch (IllegalArgumentException e) {
                    // Not a valid oid
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCustomOids: resulting DN part=" + parts.toString());
        }
        return parts;
    }
    
    /**
     * Builds a standard CSR from a PKCS#10 request
     * 
     * @param pkcs10CertificationRequest a PKCS#10 request
     * @return a CSR as a string
     */
    public static String buildCsr(final PKCS10CertificationRequest pkcs10CertificationRequest) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(BEGIN_CERTIFICATE_REQUEST + "\n");
        try {
            stringBuilder.append(new String(Base64.encode(pkcs10CertificationRequest.getEncoded())));
        } catch (IOException e) {
            throw new IllegalArgumentException("PKCS10 request could not be encoded", e);
        }
        stringBuilder.append("\n" + END_CERTIFICATE_REQUEST + "\n");
        return stringBuilder.toString();
    }
    
    /**
     * Generate SHA1 fingerprint of byte array in string representation.
     * 
     * @param in byte array to fingerprint.
     * 
     * @return String containing hex format of SHA1 fingerprint.
     */
    public static String getFingerprintAsString(byte[] in) {
        byte[] res = generateSHA1Fingerprint(in);
        return new String(Hex.encode(res));
    }
    
    /**
     * Generate SHA1 fingerprint of certificate in string representation.
     * 
     * @param cert Certificate.
     * 
     * @return String containing hex format of SHA1 fingerprint (lower case), or null if input is null.
     */
    public static String getFingerprintAsString(Certificate cert) {
        if (cert == null) {
            return null;
        }
        try {
            byte[] res = generateSHA1Fingerprint(cert.getEncoded());

            return new String(Hex.encode(res));
        } catch (CertificateEncodingException cee) {
            log.error("Error encoding certificate.", cee);
        }

        return null;
    }
    
    /**
     * Generate SHA256 fingerprint of byte array in string representation.
     * 
     * @param in byte array to fingerprint.
     * 
     * @return String containing hex format of SHA256 fingerprint.
     */
    public static String getSHA256FingerprintAsString(byte[] in) {
        byte[] res = generateSHA256Fingerprint(in);
        return new String(Hex.encode(res));
    }
    
   
    
    /**
     * Splits a DN into components.
     * @see X509NameTokenizer
     */
    public static List<String> getX500NameComponents(String dn) {
        List<String> ret = new ArrayList<>();
        if (StringUtils.isNotBlank(dn)) {
            X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
            while (tokenizer.hasMoreTokens()) {
                ret.add(tokenizer.nextToken());
            }            
        }
        return ret;
    }
    
    /**
     * Checks if a certificate is a CA certificate according to BasicConstraints. If there is no basic constraints extension on
     * a X.509 certificate, false is returned.
     * 
     * @param cert the certificate that shall be checked.
     * 
     * @return boolean true if the certificate belongs to a CA.
     */
    public static boolean isCA(X509Certificate x509cert) {
        if (x509cert.getBasicConstraints() > -1) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Gets issuer DN in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param cert Certificate
     * 
     * @return String containing the issuers DN, or null if cert is null.
     */
    public static String getIssuerDN(final X509Certificate cert) {
        return getDN(cert, 2);
    }
    
    
    /**
     * Gets issuer DN in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param cert Certificate
     * 
     * @return String containing the issuers DN, or null if cert is null.
     */
    public static String getSubjectDN(final X509Certificate cert) {
        return getDN(cert, 1);
    }
    
    /**
     * Get the subject key identifier from a certificate extensions
     * 
     * @param certificate certificate containing the extension
     * @return byte[] containing the subject key identifier, or null if it does not exist
     */
    public static byte[] getSubjectKeyId(final X509Certificate certificate) {
        if (certificate != null) {
            final ASN1Primitive asn1Sequence = getExtensionValue(certificate, Extension.subjectKeyIdentifier.getId()); // "2.5.29.14"
            if (asn1Sequence != null) {
                return SubjectKeyIdentifier.getInstance(asn1Sequence).getKeyIdentifier();
            }
        }
        return null;
    }
    
    /**
     * Get the authority key identifier from a certificate extensions
     * 
     * @param certificate certificate containing the extension
     * @return byte[] containing the authority key identifier, or null if it does not exist
     */
    public static byte[] getAuthorityKeyId(final X509Certificate certificate) {
        if (certificate != null) {
            final ASN1Primitive asn1Sequence = getExtensionValue(certificate, Extension.authorityKeyIdentifier.getId()); // "2.5.29.35"
            if (asn1Sequence != null) {
                return AuthorityKeyIdentifier.getInstance(asn1Sequence).getKeyIdentifier();
            }
        }
        return null;
    }
    
    /**
     * Get a certificate policy ID from a certificate policies extension
     * 
     * @param certificate certificate containing the extension
     * @param pos position of the policy id, if several exist, the first is as pos 0
     * @return String with the certificate policy OID, or null if an id at the given position does not exist
     * @throws IOException if extension can not be parsed
     */
    public static String getCertificatePolicyId(X509Certificate certificate, int pos) throws IOException {
        if (certificate != null) {
            final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(
                    getExtensionValue(certificate, Extension.certificatePolicies.getId()));
            if (asn1Sequence != null) {
                // Check the size so we don't ArrayIndexOutOfBounds
                if (asn1Sequence.size() >= pos + 1) {
                    return PolicyInformation.getInstance(asn1Sequence.getObjectAt(pos)).getPolicyIdentifier().getId();
                }
            }
        }
        return null;
    }
    
    /**
     * Get a list of certificate policy IDs from a certificate policies extension
     * 
     * @param certificate certificate containing the extension
     * @return List of ObjectIdentifiers, or empty list if no policies exist
     * @throws IOException if extension can not be parsed
     */
    public static List<ASN1ObjectIdentifier> getCertificatePolicyIds(X509Certificate certificate) throws IOException {
        List<ASN1ObjectIdentifier> ret = new ArrayList<>();
        if (certificate != null) {
            final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(
                    getExtensionValue(certificate, Extension.certificatePolicies.getId()));
            if (asn1Sequence != null) {
                for (ASN1Encodable asn1Encodable : asn1Sequence) {
                    PolicyInformation pi = PolicyInformation.getInstance(asn1Encodable);
                    ret.add(pi.getPolicyIdentifier());
                }
            }
        }
        return ret;
    }
    
    /**
     * Get a list of certificate policy information from a certificate policies extension
     * 
     * @param certificate certificate containing the extension
     * @return List of PolicyInformation, or empty list if no policies exist
     * @throws IOException if extension can not be parsed
     */
    public static List<PolicyInformation> getCertificatePolicies(X509Certificate certificate) throws IOException {
        List<PolicyInformation> ret = new ArrayList<>();
        if (certificate != null ) {
            final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(
                    getExtensionValue(certificate, Extension.certificatePolicies.getId()));
            if (asn1Sequence != null) {
                for (ASN1Encodable asn1Encodable : asn1Sequence) {
                    PolicyInformation pi = PolicyInformation.getInstance(asn1Encodable);
                    ret.add(pi);
                }
            }
        }
        return ret;
    }

    
    /**
     * Gets subject or issuer DN in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param cert X509Certificate
     * @param which 1 = subjectDN, anything else = issuerDN
     * 
     * @return String containing the DN, or null if cert is null.
     */
    public static String getDN(Certificate cert, final int which) {
        String ret = null;
        if (cert == null) {
            return null;
        }
        try {
            final String clazz = cert.getClass().getName();
            // The purpose of the below generateCertificate is to create a BC certificate object, because there we know how DN components
            // are handled. If we already have a BC certificate however, we can save a lot of time to not have to encode/decode it.
            final X509Certificate x509cert;
            if (clazz.contains("org.bouncycastle")) {
                x509cert = (X509Certificate) cert;
            } else {
                final CertificateFactory cf = getCertificateFactory(BouncyCastleProvider.PROVIDER_NAME);
                x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
            }
            String dn = null;
            if (which == 1) {
                dn = x509cert.getSubjectDN().toString();
            } else {
                dn = x509cert.getIssuerDN().toString();
            }
            ret = stringToBCDNString(dn);
        } catch (CertificateException ce) {
            log.info("Could not get DN from X509Certificate. " + ce.getMessage());
            log.debug("", ce);
            return null;
        }
        return ret;
    }
    
    /**
     * Returns the parent DN of a DN string, e.g. if the input is
     * "cn=User,dc=example,dc=com" then it would return "dc=example,dc=com".
     * Returns an empty string if there is no parent DN.
     */
    public static String getParentDN(String dn) {
        final X509NameTokenizer tokenizer = new X509NameTokenizer(dn);
        tokenizer.nextToken();
        return tokenizer.getRemainingString();
    }
    
    public static X500Name stringToUnorderedX500Name(String dn, final X500NameStyle nameStyle) {
        if (log.isTraceEnabled()) {
            log.trace(">stringToUnorderedX500Name: " + dn);
        }
        if (dn == null) {
            return null;
        }
        // If the entire DN is quoted (which is strange but legacy), we just remove these quotes and carry on
        if (dn.length() > 2 && dn.charAt(0) == '"' && dn.charAt(dn.length() - 1) == '"') {
            dn = dn.substring(1, dn.length() - 1);
        }
        final X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
        // split DN string into RDNs, but if it is empty, don't try to split it
        // this means an empty X500Name will be returned, as according to the javadoc
        if (dn.length() > 0) {            
            RDN[] rdns;
            // Will throw an IllegalArgumentException if the DN is badly formatted
            rdns = IETFUtils.rDNsFromString(dn, nameStyle);

            for (RDN rdn: rdns) {
                if (rdn.isMultiValued()) {
                    AttributeTypeAndValue avas[] = rdn.getTypesAndValues();
                    nameBuilder.addMultiValuedRDN(avas);
                } else {
                    AttributeTypeAndValue ava = rdn.getFirst();
                    nameBuilder.addRDN(ava);
                }
            }

            // This was the old legacy way we did the IETFUtils.rDNsFromString manually before
            // Keep it for reference at until EJBCA 7.2 or something, just to aid in potential support cases
            //        boolean quoted = false;
            //        boolean escapeNext = false;
            //        int currentStartPosition = -1;
            //        String currentPartName = null;
            //        for (int i = 0; i < dn.length(); i++) {
            //            final char current = dn.charAt(i);
            //            // Toggle quoting for every non-escaped "-char
            //            if (!escapeNext && current == '"') {
            //                quoted = !quoted;
            //            }
            //            // If there is an unescaped and unquoted =-char the proceeding chars is a part name
            //            if (currentStartPosition == -1 && !quoted && !escapeNext && current == '=' && 1 <= i) {
            //                // Trim spaces (e.g. "O =value")
            //                int endIndexOfPartName = i;
            //                while (endIndexOfPartName > 0 && dn.charAt(endIndexOfPartName - 1) == ' ') {
            //                    endIndexOfPartName--;
            //                }
            //                int startIndexOfPartName = endIndexOfPartName - 1;
            //                final String endOfPartNameSearchChars = ", +";
            //                while (startIndexOfPartName > 0 && (endOfPartNameSearchChars.indexOf(dn.charAt(startIndexOfPartName - 1)) == -1)) {
            //                    startIndexOfPartName--;
            //                }
            //                currentPartName = dn.substring(startIndexOfPartName, endIndexOfPartName);
            //                currentStartPosition = i + 1;
            //            }
            //            // When we have found a start marker, we need to be on the lookout for the ending marker
            //            if (currentStartPosition != -1 && ((!quoted && !escapeNext && (current == ',' || current == '+')) || i == dn.length() - 1)) {
            //                int endPosition = (i == dn.length() - 1) ? dn.length() - 1 : i - 1;
            //                // Remove white spaces from the end of the value
            //                while (endPosition > currentStartPosition && dn.charAt(endPosition) == ' ') {
            //                    endPosition--;
            //                }
            //                // Remove white spaces from the beginning of the value
            //                while (endPosition > currentStartPosition && dn.charAt(currentStartPosition) == ' ') {
            //                    currentStartPosition++;
            //                }
            //                // Only return the inner value if the part is quoted
            //                if (currentStartPosition < dn.length() && dn.charAt(currentStartPosition) == '"' && dn.charAt(endPosition) == '"') {
            //                    currentStartPosition++;
            //                    endPosition--;
            //                }
            //                String currentValue = dn.substring(currentStartPosition, endPosition + 1);
            //                // Unescape value (except escaped #) since the nameBuilder will double each escape
            //                currentValue = unescapeValue(new StringBuilder(currentValue)).toString();
            //                try {
            //                    // -- First search the OID by name in declared OID's
            //                    ASN1ObjectIdentifier oid = DnComponents.getOid(currentPartName);
            //                    // -- If isn't declared, we try to create it
            //                    if (oid == null) {
            //                        oid = new ASN1ObjectIdentifier(currentPartName);
            //                    }
            //                    nameBuilder.addRDN(oid, currentValue);
            //                } catch (IllegalArgumentException e) {
            //                    // If it is not an OID we will ignore it
            //                    log.warn("Unknown DN component ignored and silently dropped: " + currentPartName);
            //                }
            //                // Reset markers
            //                currentStartPosition = -1;
            //                currentPartName = null;
            //            }
            //            if (escapeNext) {
            //                // This character was escaped, so don't escape the next one
            //                escapeNext = false;
            //            } else {
            //                if (!quoted && current == '\\') {
            //                    // This escape character is not escaped itself, so the next one should be
            //                    escapeNext = true;
            //                }
            //            }
            //        }
        }      
        // finally builds X500 name 
        final X500Name x500Name = nameBuilder.build();
        if (log.isTraceEnabled()) {
            log.trace("<stringToUnorderedX500Name: x500Name=" + x500Name.toString());
        }
        return x500Name;
    }
    
    /**
     * (This method intentionally has package level visibility to be able to be invoked from JUnit tests.)
     * @param seq
     * @return The extension values encoded as an permanentIdentifierString
     */
    protected static String getPermanentIdentifierStringFromSequence(ASN1Sequence seq) {
        if (seq != null) {
            // First in sequence is the object identifier, that we must check
            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            if (id.getId().equals(PERMANENTIDENTIFIER_OBJECTID)) {
                String identifierValue = null;
                String assigner = null;

                // Get the PermanentIdentifier sequence
                ASN1TaggedObject oobj = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                // Due to bug in java cert.getSubjectAltName regarding OtherName, it can be tagged an extra time...
                ASN1Primitive obj = oobj.getObject();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                ASN1Sequence piSeq = ASN1Sequence.getInstance(obj);

                Enumeration<?> e = piSeq.getObjects();
                if (e.hasMoreElements()) {
                    Object element = e.nextElement();
                    if (element instanceof DERUTF8String) {
                        identifierValue = ((DERUTF8String) element).getString();
                        if (e.hasMoreElements()) {
                            element = e.nextElement();
                        }
                    }
                    if (element instanceof ASN1ObjectIdentifier) {
                        assigner = ((ASN1ObjectIdentifier) element).getId();
                    }
                }

                StringBuilder buff = new StringBuilder();
                if (identifierValue != null) {
                    buff.append(escapePermanentIdentifierValue(identifierValue));
                }
                buff.append(PERMANENTIDENTIFIER_SEP);
                if (assigner != null) {
                    buff.append(assigner);
                }
                return buff.toString();
            }
        }
        return null;
    }
    
    /**
     * Helper method for getting kerberos 5 principal name (altName, OtherName)
     * 
     * Krb5PrincipalName is an OtherName Subject Alternative Name
     * 
     * String representation is in form "principalname1/principalname2@realm"
     * 
     * KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }
     * 
     * Realm ::= KerberosString
     * 
     * PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
     * 
     * The new (post-RFC 1510) type KerberosString, defined below, is a GeneralString that is constrained to contain only characters in IA5String.
     * 
     * KerberosString ::= GeneralString (IA5String)
     * 
     * Int32 ::= INTEGER (-2147483648..2147483647) -- signed values representable in 32 bits
     * 
     * @param seq the OtherName sequence
     * @return String with the krb5 name in the form of "principal1/principal2@realm" or null if the altName does not exist
     */
    protected static String getKrb5PrincipalNameFromSequence(ASN1Sequence seq) {
        String ret = null;
        if (seq != null) {
            // First in sequence is the object identifier, that we must check
            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            if (id.getId().equals(KRB5PRINCIPAL_OBJECTID)) {
                // Get the KRB5PrincipalName sequence
                ASN1TaggedObject oobj = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                // Due to bug in java cert.getSubjectAltName regarding OtherName, it can be tagged an extra time...
                ASN1Primitive obj = oobj.getObject();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                ASN1Sequence krb5Seq = ASN1Sequence.getInstance(obj);
                // Get the Realm tagged as 0
                ASN1TaggedObject robj = ASN1TaggedObject.getInstance(krb5Seq.getObjectAt(0));
                ASN1GeneralString realmObj = ASN1GeneralString.getInstance(robj.getObject());
                String realm = realmObj.getString();
                // Get the PrincipalName tagged as 1
                ASN1TaggedObject pobj = ASN1TaggedObject.getInstance(krb5Seq.getObjectAt(1));
                // This is another sequence of type and name
                ASN1Sequence nseq = ASN1Sequence.getInstance(pobj.getObject());
                // Get the name tagged as 1
                ASN1TaggedObject nobj = ASN1TaggedObject.getInstance(nseq.getObjectAt(1));
                // The name is yet another sequence of GeneralString
                ASN1Sequence sseq = ASN1Sequence.getInstance(nobj.getObject());
                @SuppressWarnings("unchecked")
                Enumeration<ASN1Object> en = sseq.getObjects();
                while (en.hasMoreElements()) {
                    ASN1GeneralString str = ASN1GeneralString.getInstance(en.nextElement());
                    if (ret != null) {
                        ret += "/" + str.getString();
                    } else {
                        ret = str.getString();
                    }
                }
                // Add the realm in the end so we have "principal@realm"
                ret += "@" + realm;
            }
        }
        return ret;
    }
    
    /**
     * SubjectAltName ::= GeneralNames
     * 
     * GeneralNames :: = SEQUENCE SIZE (1..MAX) OF GeneralName
     * 
     * GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1] IA5String, dNSName [2] IA5String, x400Address [3] ORAddress, directoryName [4]
     * Name, ediPartyName [5] EDIPartyName, uniformResourceIdentifier [6] IA5String, iPAddress [7] OCTET STRING, registeredID [8] OBJECT IDENTIFIER}
     * 
     * SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uniformResourceIdentifier=<http://host.com/>, iPAddress=<address>,
     * guid=<globally unique id>, directoryName=<LDAP escaped DN>, permanentIdentifier=<identifierValue/assigner|identifierValue|/assigner|/>,
     * subjectIdentificationMethod=<Subject Identification Method values or parameters>, registeredID=<object identifier>,
     * xmppAddr=<RFC6120 XmppAddr>, srvName=<RFC4985 SRVName>, fascN=<FIPS 201-2 PIV FASC-N>
     * 
     * Supported altNames are upn, krb5principal, rfc822Name, uniformResourceIdentifier, dNSName, iPAddress, directoryName, permanentIdentifier
     * 
     * @author Marco Ferrante, (c) 2005 CSITA - University of Genoa (Italy)
     * @author Tomas Gustavsson
     * @param x509cert containing alt names
     * @return String containing altNames of form
     *         "rfc822Name=email, dNSName=hostname, uniformResourceIdentifier=uri, iPAddress=ip, upn=upn, directoryName=CN=testDirName|dir|name", permanentIdentifier=identifierValue/assigner or
     *         empty string if no altNames exist. Values in returned String is from CertTools constants. AltNames not supported are simply not shown
     *         in the resulting string.
     */
    public static String getSubjectAlternativeName(X509Certificate x509cert) {
        if (log.isTraceEnabled()) {
            log.trace(">getSubjectAlternativeName");
        }
        String result = "";

        Collection<List<?>> altNames = null;

        try {
            altNames = x509cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new RuntimeException("Could not parse certificate", e);
        }

        if (altNames == null) {
            return null;
        }
        final Iterator<List<?>> iter = altNames.iterator();
        String append = new String();
        List<?> item = null;
        Integer type = null;
        Object value = null;
        while (iter.hasNext()) {
            item = iter.next();
            type = (Integer) item.get(0);
            value = item.get(1);
            if (!StringUtils.isEmpty(result)) {
                // Result already contains one altname, so we have to add comma if there are more altNames
                append = ", ";
            }
            String rdn = null;
            switch (type.intValue()) {
            case 0:
                // OtherName, can be a lot of different things
                final ASN1Sequence sequence = getAltnameSequence(item);
                final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
                switch (oid.getId()) {
                case UPN_OBJECTID:
                    rdn = UPN + "=" + getUTF8StringFromSequence(sequence, UPN_OBJECTID);
                    break;
                case PERMANENTIDENTIFIER_OBJECTID:
                    rdn = PERMANENTIDENTIFIER + "=" + getPermanentIdentifierStringFromSequence(sequence);
                    break;
                case KRB5PRINCIPAL_OBJECTID:
                    rdn = KRB5PRINCIPAL + "=" + getKrb5PrincipalNameFromSequence(sequence);
                    break;
                case RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD_OBJECTID:
                    final String sim = RFC4683Tools.getSimStringSequence(sequence);
                    rdn = RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD + "=" + sim;
                    break;
                case GUID_OBJECTID:
                    rdn = GUID + "=" + getGUIDStringFromSequence(sequence);
                    break;
                case XMPPADDR_OBJECTID:
                    rdn = XMPPADDR + "=" + getUTF8StringFromSequence(sequence, XMPPADDR_OBJECTID);
                    break;
                case SRVNAME_OBJECTID:
                    rdn = SRVNAME + "=" + getIA5StringFromSequence(sequence, SRVNAME_OBJECTID);
                    break;
                case FASCN_OBJECTID:
                    // PIV FASC-N (FIPS 201-2) is an OCTET STRING, we'll return if as a hex encoded String
                    rdn = FASCN + "=" + new String(Hex.encode(getOctetStringFromSequence(sequence, FASCN_OBJECTID)));
                    break;
                }
                ;
                break;
            case 1:
                rdn = EMAIL + "=" + (String) value;
                break;
            case 2:
                rdn = DNS + "=" + (String) value;
                break;
            case 3: // SubjectAltName of type x400Address not supported
                break;
            case 4:
                rdn = DIRECTORYNAME + "=" + (String) value;
                break;
            case 5: // SubjectAltName of type ediPartyName not supported
                break;
            case 6:
                rdn = URI + "=" + (String) value;
                break;
            case 7:
                rdn = IPADDR + "=" + (String) value;
                break;
            case 8:
                // OID names are returned as Strings according to the JDK X509Certificate javadoc
                rdn = REGISTEREDID + "=" + (String) value;
                break;
            default: // SubjectAltName of unknown type
                break;
            }
            if (rdn != null) {
                // The rdn might contain commas, so escape it.
                result += append + escapeFieldValue(rdn);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getSubjectAlternativeName: " + result);
        }
        if (StringUtils.isEmpty(result)) {
            return null;
        }

        return result;
    }
    
    /**
     * Gets the Microsoft specific UPN altName (altName, OtherName).
     * 
     * UPN is an OtherName Subject Alternative Name:
     * 
     * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }
     * 
     * UPN ::= UTF8String
     * 
     * @param cert certificate containing the extension
     * @return String with the UPN name or null if the altName does not exist
     */
    public static String getUPNAltName(X509Certificate cert) throws CertificateParsingException {
        return getUTF8AltNameOtherName(cert, UPN_OBJECTID);
    }
    
    /**
     * Gets a UTF8 OtherName altName (altName, OtherName).
     * 
     * Like UPN and XmpAddr
     * 
     * An OtherName Subject Alternative Name:
     * 
     * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }
     * 
     * UPN ::= UTF8String
     * (subjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:username@some.domain)
     * XmppAddr ::= UTF8String
     * (subjectAltName=otherName:1.3.6.1.5.5.7.8.5;UTF8:username@some.domain)
     * 
     * UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
     * XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
     * SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
     * 
     * @param cert certificate containing the extension
     * @param oid the OID of the OtherName
     * @return String with the UTF8 name or null if the altName does not exist
     */
    public static String getUTF8AltNameOtherName(final X509Certificate x509cert, final String oid) throws CertificateParsingException {
        String ret = null;
        Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
        if (altNames != null) {
            for (final List<?> next : altNames) {
                ret = getUTF8StringFromSequence(getAltnameSequence(next), oid);
                if (ret != null) {
                    break;
                }
            }
        }
        return ret;
    }
    
    /**
     * Gets the Microsoft specific GUID altName, that is encoded as an octet string.
     * 
     * @param cert certificate containing the extension
     * @return String with the hex-encoded GUID byte array or null if the altName does not exist
     */
    public static String getGuidAltName(X509Certificate x509cert) throws CertificateParsingException {
        Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
        if (altNames != null) {
            Iterator<List<?>> i = altNames.iterator();
            while (i.hasNext()) {
                ASN1Sequence seq = getAltnameSequence(i.next());
                if (seq != null) {
                    String guid = getGUIDStringFromSequence(seq);
                    if (guid != null) {
                        return guid;
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * From an altName string as defined in getSubjectAlternativeName
     * 
     * @param altName
     * @return ASN.1 GeneralNames
     * @see #getSubjectAlternativeName
     */
    public static GeneralNames getGeneralNamesFromAltName(final String altName) {
        if (log.isTraceEnabled()) {
            log.trace(">getGeneralNamesFromAltName: " + altName);
        }
        final ASN1EncodableVector vec = new ASN1EncodableVector();

        for (final String email : getEmailFromDN(altName)) {
            vec.add(new GeneralName(1, /*new DERIA5String(iter.next())*/email));
        }

        for (final String dns : getPartsFromDN(altName, DNS)) {
            vec.add(new GeneralName(2, new DERIA5String(dns)));
        }

        final String directoryName = getDirectoryStringFromAltName(altName);
        if (directoryName != null) {
            final X500Name x500DirectoryName = new X500Name(CeSecoreNameStyle.INSTANCE, directoryName);
            final GeneralName gn = new GeneralName(4, x500DirectoryName);
            vec.add(gn);
        }

        for (final String uri : getPartsFromDN(altName, URI)) {
            vec.add(new GeneralName(6, new DERIA5String(uri)));
        }
        for (final String uri : getPartsFromDN(altName, URI1)) {
            vec.add(new GeneralName(6, new DERIA5String(uri)));
        }
        for (final String uri : getPartsFromDN(altName, URI2)) {
            vec.add(new GeneralName(6, new DERIA5String(uri)));
        }

        for (final String addr : getPartsFromDN(altName, IPADDR)) {
            final byte[] ipoctets = StringTools.ipStringToOctets(addr);
            if (ipoctets.length > 0) {
                final GeneralName gn = new GeneralName(7, new DEROctetString(ipoctets));
                vec.add(gn);
            } else {
                log.error("Cannot parse/encode ip address, ignoring: " + addr);
            }
        }
        for (final String oid : getPartsFromDN(altName, REGISTEREDID)) {
            vec.add(new GeneralName(GeneralName.registeredID, oid));
        }

        // UPN is an OtherName see method getUpn... for asn.1 definition
        for (final String upn : getPartsFromDN(altName, UPN)) {
            final ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(UPN_OBJECTID));
            v.add(new DERTaggedObject(true, 0, new DERUTF8String(upn)));
            vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
        }

        // XmpAddr is an OtherName see method getUTF8String...... for asn.1 definition
        for (final String xmppAddr : getPartsFromDN(altName, XMPPADDR)) {
            final ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(XMPPADDR_OBJECTID));
            v.add(new DERTaggedObject(true, 0, new DERUTF8String(xmppAddr)));
            vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
        }

        // srvName is an OtherName see method getIA5String...... for asn.1 definition
        for (final String srvName : getPartsFromDN(altName, SRVNAME)) {
            final ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(SRVNAME_OBJECTID));
            v.add(new DERTaggedObject(true, 0, new DERIA5String(srvName)));
            vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
        }

        // FASC-N is an OtherName see method getOctetString...... for asn.1 definition (PIV FIPS 201-2)
        // We take the input as being a hex encoded octet string
        for (final String fascN : getPartsFromDN(altName, FASCN)) {
            final ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1ObjectIdentifier(FASCN_OBJECTID));
            v.add(new DERTaggedObject(true, 0, new DEROctetString(Hex.decode(fascN))));
            vec.add(GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v))));
        }

        // PermanentIdentifier is an OtherName see method getPermananentIdentifier... for asn.1 definition
        for (final String permanentIdentifier : getPartsFromDN(altName, PERMANENTIDENTIFIER)) {
            final String[] values = getPermanentIdentifierValues(permanentIdentifier);
            final ASN1EncodableVector v = new ASN1EncodableVector(); // this is the OtherName
            v.add(new ASN1ObjectIdentifier(PERMANENTIDENTIFIER_OBJECTID));
            // First the PermanentIdentifier sequence
            final ASN1EncodableVector piSeq = new ASN1EncodableVector();
            if (values[0] != null) {
                piSeq.add(new DERUTF8String(values[0]));
            }
            if (values[1] != null) {
                piSeq.add(new ASN1ObjectIdentifier(values[1]));
            }
            v.add(new DERTaggedObject(true, 0, new DERSequence(piSeq)));
            // GeneralName gn = new GeneralName(new DERSequence(v), 0);
            final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
            vec.add(gn);
        }

        for (final String guid : getPartsFromDN(altName, GUID)) {
            final ASN1EncodableVector v = new ASN1EncodableVector();
            final String dashRemovedGuid = guid.replace("-", "");
            byte[] guidbytes = Hex.decode(dashRemovedGuid);
            if (guidbytes != null) {
                v.add(new ASN1ObjectIdentifier(GUID_OBJECTID));
                v.add(new DERTaggedObject(true, 0, new DEROctetString(guidbytes)));
                final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
                vec.add(gn);
            } else {
                log.error("Cannot decode hexadecimal guid, ignoring: " + guid);
            }
        }

        // Krb5PrincipalName is an OtherName, see method getKrb5Principal...for ASN.1 definition
        for (final String principalString : getPartsFromDN(altName, KRB5PRINCIPAL)) {
            // Start by parsing the input string to separate it in different parts
            if (log.isDebugEnabled()) {
                log.debug("principalString: " + principalString);
            }
            // The realm is the last part moving back until an @
            final int index = principalString.lastIndexOf('@');
            String realm = "";
            if (index > 0) {
                realm = principalString.substring(index + 1);
            }
            if (log.isDebugEnabled()) {
                log.debug("realm: " + realm);
            }
            // Now we can have several principals separated by /
            final ArrayList<String> principalarr = new ArrayList<>();
            int jndex = 0;
            int bindex = 0;
            while (jndex < index) {
                // Loop and add all strings separated by /
                jndex = principalString.indexOf('/', bindex);
                if (jndex == -1) {
                    jndex = index;
                }
                String s = principalString.substring(bindex, jndex);
                if (log.isDebugEnabled()) {
                    log.debug("adding principal name: " + s);
                }
                principalarr.add(s);
                bindex = jndex + 1;
            }

            // Now we must construct the rather complex asn.1...
            final ASN1EncodableVector v = new ASN1EncodableVector(); // this is the OtherName
            v.add(new ASN1ObjectIdentifier(KRB5PRINCIPAL_OBJECTID));

            // First the Krb5PrincipalName sequence
            final ASN1EncodableVector krb5p = new ASN1EncodableVector();
            // The realm is the first tagged GeneralString
            krb5p.add(new DERTaggedObject(true, 0, new DERGeneralString(realm)));
            // Second is the sequence of principal names, which is at tagged position 1 in the krb5p
            final ASN1EncodableVector principals = new ASN1EncodableVector();
            // According to rfc4210 the type NT-UNKNOWN is 0, and according to some other rfc this type should be used...
            principals.add(new DERTaggedObject(true, 0, new ASN1Integer(0)));
            // The names themselves are yet another sequence
            final ASN1EncodableVector names = new ASN1EncodableVector();
            for (final String principalName : principalarr) {
                names.add(new DERGeneralString(principalName));
            }
            principals.add(new DERTaggedObject(true, 1, new DERSequence(names)));
            krb5p.add(new DERTaggedObject(true, 1, new DERSequence(principals)));

            v.add(new DERTaggedObject(true, 0, new DERSequence(krb5p)));
            final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
            vec.add(gn);
        }

        // SIM is an OtherName. See RFC-4683
        for (final String internalSimString : getPartsFromDN(altName, RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD)) {
            if (StringUtils.isNotBlank(internalSimString)) {
                final String[] tokens = internalSimString.split(RFC4683Tools.LIST_SEPARATOR); 
                if (tokens.length==3) {
                    ASN1Primitive gn = RFC4683Tools.createSimGeneralName(tokens[0], tokens[1], tokens[2]);
                    vec.add(gn);
                    if (log.isDebugEnabled()) {
                        log.debug("SIM GeneralName added: " + gn.toString());
                    }
                }
            }            
        }
        
        // To support custom OIDs in altNames, they must be added as an OtherName of plain type UTF8String
        for (final String oid : getCustomOids(altName)) {
            for (final String oidValue : getPartsFromDN(altName, oid)) {
                final ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(new ASN1ObjectIdentifier(oid));
                v.add(new DERTaggedObject(true, 0, new DERUTF8String(oidValue)));
                final ASN1Primitive gn = new DERTaggedObject(false, 0, new DERSequence(v));
                vec.add(gn);
            }
        }

        if (vec.size() > 0) {
            return GeneralNames.getInstance(new DERSequence(vec));
        }
        return null;
    }
    
    /**
     * Obtain the directory string for the directoryName generation form the Subject Alternative Name String.
     * 
     * @param altName
     * @return
     */
    private static String getDirectoryStringFromAltName(String altName) {
        String directoryName = getPartFromDN(altName, DIRECTORYNAME);
        // DNFieldExtractor dnfe = new DNFieldExtractor(altName, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        // String directoryName = dnfe.getField(DNFieldExtractor.DIRECTORYNAME, 0);
        /** TODO: Validate or restrict the directoryName Fields? */
        return ("".equals(directoryName) ? null : directoryName);
    } 
    
    /**
     * (This method intentionally has package level visibility to be able to be invoked from JUnit tests.)
     * @param permanentIdentifierString
     * @return A two elements String array with the extension values
     */
    protected static String[] getPermanentIdentifierValues(String permanentIdentifierString) {
        String[] result = new String[2];
        int sepPos = permanentIdentifierString.lastIndexOf(PERMANENTIDENTIFIER_SEP);
        if (sepPos == -1) {
            if (!permanentIdentifierString.isEmpty()) {
                result[0] = unescapePermanentIdentifierValue(permanentIdentifierString);
            }
        } else if (sepPos == 0) {
            if (permanentIdentifierString.length() > 1) {
                result[1] = permanentIdentifierString.substring(1);
            }
        } else if (permanentIdentifierString.charAt(sepPos - PERMANENTIDENTIFIER_SEP.length()) != '\\') {
            result[0] = unescapePermanentIdentifierValue(permanentIdentifierString.substring(0, sepPos));
            if (permanentIdentifierString.length() > sepPos + PERMANENTIDENTIFIER_SEP.length()) {
                result[1] = permanentIdentifierString.substring(sepPos + 1);
            }
        }
        return result;
    }
    
    /**
     * Gets the Permanent Identifier (altName, OtherName).
     * 
     * permanentIdentifier is an OtherName Subject Alternative Name:
     * 
     * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }
     * 
     * -- Permanent Identifier
     *
     *   permanentIdentifier OTHER-NAME ::=
     * { PermanentIdentifier IDENTIFIED BY id-on-permanentIdentifier }
     *
     * PermanentIdentifier ::= SEQUENCE {
     *  identifierValue    UTF8String             OPTIONAL,
     *                  -- if absent, use the serialNumber attribute
     *                  -- if there is a single such attribute present
     *                  -- in the subject DN
     *  assigner           OBJECT IDENTIFIER      OPTIONAL
     *                  -- if absent, the assigner is
     *                  -- the certificate issuer
     * }
     * 
     * @param cert certificate containing the extension
     * @return String with the permanentIdentifier name or null if the altName does not exist
     */
    public static String getPermanentIdentifierAltName(X509Certificate x509cert) throws CertificateParsingException {
        String ret = null;
        Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
        if (altNames != null) {
            Iterator<List<?>> i = altNames.iterator();
            while (i.hasNext()) {
                ASN1Sequence seq = getAltnameSequence(i.next());
                ret = getPermanentIdentifierStringFromSequence(seq);
                if (ret != null) {
                    break;
                }
            }
        }
        return ret;
    }
    
    /**
     * GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1] IA5String, dNSName [2] IA5String, x400Address [3] ORAddress, directoryName [4]
     * Name, ediPartyName [5] EDIPartyName, uniformResourceIdentifier [6] IA5String, iPAddress [7] OCTET STRING, registeredID [8] OBJECT IDENTIFIER}
     * 
     * @param tag the no tag 0-8
     * @param value the ASN1Encodable value as returned by GeneralName.getName()
     * @return String in form rfc822Name=<email> or uri=<uri> etc
     * @throws IOException
     * @see #getSubjectAlternativeName
     */
    public static String getGeneralNameString(int tag, ASN1Encodable value) throws IOException {
        String ret = null;
        switch (tag) {
        case 0:
        {
            final ASN1Sequence sequence = getAltnameSequence(value.toASN1Primitive().getEncoded());
            final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
            switch(oid.getId()) {
                case UPN_OBJECTID:
                    ret = UPN + "=" + getUTF8StringFromSequence(sequence, UPN_OBJECTID);
                    break;
                case PERMANENTIDENTIFIER_OBJECTID:
                    ret = PERMANENTIDENTIFIER + "=" + getPermanentIdentifierStringFromSequence(sequence);
                    break;
                case KRB5PRINCIPAL_OBJECTID:
                    ret = KRB5PRINCIPAL + "=" + getKrb5PrincipalNameFromSequence(sequence);
                    break;
                case RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD_OBJECTID:
                    ret = RFC4683Tools.SUBJECTIDENTIFICATIONMETHOD + "=" + RFC4683Tools.getSimStringSequence(sequence);
                    break;
                case XMPPADDR_OBJECTID:
                    ret = XMPPADDR + "=" + getUTF8StringFromSequence(sequence, XMPPADDR_OBJECTID);
                    break;
                case SRVNAME_OBJECTID:
                    ret = SRVNAME + "=" + getIA5StringFromSequence(sequence, SRVNAME_OBJECTID);
                    break;
                case FASCN_OBJECTID:
                    ret = FASCN + "=" + new String(Hex.encode(getOctetStringFromSequence(sequence, FASCN_OBJECTID)));
                    break;
            };
            break;
        }
        case 1:
            ret = EMAIL + "=" + ASN1IA5String.getInstance(value).getString();
            break;
        case 2:
            ret = DNS + "=" + ASN1IA5String.getInstance(value).getString();
            break;
        case 3: // SubjectAltName of type x400Address not supported
            break;
        case 4:
            final X500Name name = X500Name.getInstance(value);
            ret = DIRECTORYNAME + "=" + name.toString();
            break;
        case 5: // SubjectAltName of type ediPartyName not supported
            break;
        case 6:
            ret = URI + "=" + ASN1IA5String.getInstance(value).getString();
            break;
        case 7:
            ASN1OctetString oct = ASN1OctetString.getInstance(value);
            ret = IPADDR + "=" + StringTools.ipOctetsToString(oct.getOctets());
            break;
        case 8:
            // BC GeneralName stores the actual object value, which is an OID
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(value);
            ret = REGISTEREDID+ "=" + oid.getId();
            break;            
        default: // SubjectAltName of unknown type
            break;
        }
        return ret;
    }
    
    /**
     * Convenience method for getting an email addresses from a DN. Uses {@link #getPartsFromDN(String,String)} internally, and searches for
     * {@link #EMAIL}, {@link #EMAIL1}, {@link #EMAIL2}, {@link #EMAIL3} and returns the first one found.
     * 
     * @param dn the DN
     * 
     * @return ArrayList containing email or empty list if email is not present
     */
    public static List<String> getEmailFromDN(String dn) {
        if (log.isTraceEnabled()) {
            log.trace(">getEmailFromDN(" + dn + ")");
        }
        List<String> ret = new ArrayList<>();
        for (int i = 0; i < EMAILIDS.length; i++) {
            List<String> emails = getPartsFromDN(dn, EMAILIDS[i]);
            if (!emails.isEmpty()) {
                ret.addAll(emails);
            }

        }
        if (log.isTraceEnabled()) {
            log.trace("<getEmailFromDN(" + dn + "): " + ret.size());
        }
        return ret;
    }
    
    /**
     * Search for e-mail address, first in SubjectAltName (as in PKIX recommendation) then in subject DN. Original author: Marco Ferrante, (c) 2005
     * CSITA - University of Genoa (Italy)
     * 
     * @param certificate
     * @return subject email or null if not present in certificate
     */
    public static String getEMailAddress(X509Certificate x509cert) {
        log.debug("Searching for EMail Address in SubjectAltName");
        if (x509cert == null) {
            return null;
        }
        try {
            if (x509cert.getSubjectAlternativeNames() != null) {
                for (List<?> item : x509cert.getSubjectAlternativeNames()) {
                    Integer type = (Integer) item.get(0);
                    if (type == 1) {
                        return (String) item.get(1);
                    }
                }
            }
        } catch (CertificateParsingException e) {
            log.error("Error parsing certificate: ", e);
        }
        log.debug("Searching for EMail Address in Subject DN");
        List<String> emails = getEmailFromDN(x509cert.getSubjectDN().getName());
        if (!emails.isEmpty()) {
            return emails.get(0);
        }
        return null;
    }
    
    
    /**
     * Gets Serial number of the certificate.
     * 
     * @param cert an X509Certificate
     * 
     * @return BigInteger containing the certificate serial number. 
     * @throws IllegalArgumentException if null input
     */
    public static BigInteger getSerialNumber(X509Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("Null input");
        }
        X509Certificate xcert = (X509Certificate) cert;
        return xcert.getSerialNumber();
    }
    
    /**
     * Gets Serial number of the certificate as a string, i.e. a HEX encoded BigInteger
     * <p>
     * The value is normalized (uppercase without leading zeros), so there's no need to normalize the returned value.
     * 
     * @param cert an {@link X509Certificate}
     * 
     * @return String to be displayed or used in RoleMember objects
     * @throws IllegalArgumentException if input is null 
     */
    public static String getSerialNumberAsString(X509Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("getSerialNumber: cert is null");
        }
        return cert.getSerialNumber().toString(16).toUpperCase();
    }
    
    /**
     * Gets a serial number in numeric form, it takes - either a hex encoded integer with length != 5 (x.509 certificate) - 5 letter numeric string
     * (cvc), will convert the number to an int - 5 letter alfanumeric string vi some numbers in it (cvc), will convert the numbers in it to a numeric
     * string (remove the letters) and convert to int - 5 letter alfanumeric string with only letters (cvc), will convert to integer from string with
     * radix 36
     * 
     * @param sernoString
     * @return BigInteger
     */
    public static BigInteger getSerialNumberFromString(String sernoString) {
        if (sernoString == null) {
            throw new IllegalArgumentException("getSerialNumberFromString: sernoString is null");
        }
        BigInteger ret;
        try {
            if (sernoString.length() != 5) {
                // This can not be a CVC certificate sequence, so it must be a hex encoded regular certificate serial number
                ret = new BigInteger(sernoString, 16);
            } else {
                // We try to handle the different cases of CVC certificate sequences, see StringTools.KEY_SEQUENCE_FORMAT
                if (NumberUtils.isNumber(sernoString)) {
                    ret = NumberUtils.createBigInteger(sernoString);
                } else {
                    // check if input is hexadecimal
                    log.info("getSerialNumber: Sequence is not a numeric string, trying to extract numerical sequence part.");
                    StringBuilder buf = new StringBuilder();
                    for (int i = 0; i < sernoString.length(); i++) {
                        char c = sernoString.charAt(i);
                        if (CharUtils.isAsciiNumeric(c)) {
                            buf.append(c);
                        }
                    }
                    if (buf.length() > 0) {
                        ret = NumberUtils.createBigInteger(buf.toString());
                    } else {
                        log.info("getSerialNumber: can not extract numeric sequence part, trying alfanumeric value (radix 36).");
                        if (sernoString.matches("[0-9A-Z]{1,5}")) {
                            int numSeq = Integer.parseInt(sernoString, 36);
                            ret = BigInteger.valueOf(numSeq);
                        } else {
                            log.info("getSerialNumber: Sequence does not contain any numeric parts, returning 0.");
                            ret = BigInteger.valueOf(0);
                        }
                    }
                }
            }
        } catch (NumberFormatException e) {
            // If we can't make the sequence into a serial number big integer, set it to 0
            log.debug("getSerialNumber: NumberFormatException for sequence: " + sernoString);
            ret = BigInteger.valueOf(0);
        }
        return ret;
    }
    
    /**
     * Generate a selfsigned certificate.
     * 
     * @param dn subject and issuer DN
     * @param validity in days
     * @param policyId policy string ('2.5.29.32.0') or null
     * @param privKey private key
     * @param pubKey public key
     * @param sigAlg signature algorithm, you can use one of the contants AlgorithmConstants.SIGALG_XXX
     * @param isCA boolean true or false
     * 
     * @return X509Certificate, self signed
     * 
     * @throws IOException 
     * @throws CertificateException 
     * @throws OperatorCreationException 
     */
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg,
            boolean isCA) throws OperatorCreationException, CertificateException  {
        return genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, BouncyCastleProvider.PROVIDER_NAME);
    }
    
    /** Generates a self signed certificate with keyUsage X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, i.e. a CA certificate
     * @throws IOException 
     * @throws OperatorCreationException 
     * @throws CertificateParsingException 
     * 
     */
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg,
            boolean isCA, String provider, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
        final int keyUsage;
        if (isCA) {
            keyUsage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        } else {
            keyUsage = 0;
        }
        return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyUsage, null, null, provider, ldapOrder);
    } 
    
    /** Generates a self signed certificate with keyUsage X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, i.e. a CA certificate
     * 
     */
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg,
            boolean isCA, String provider) throws OperatorCreationException, CertificateException {
        return genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, provider, true);
    }
    
    /**
     * Generate a selfsigned certificate with possibility to specify key usage.
     * 
     * @param dn subject and issuer DN
     * @param validity in days
     * @param policyId policy string ('2.5.29.32.0') or null
     * @param privKey private key
     * @param pubKey public key
     * @param sigAlg signature algorithm, you can use one of the contants AlgorithmConstants.SIGALG_XXX
     * @param isCA boolean true or false
     * @param keyusage as defined by constants in X509KeyUsage
     */
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
        return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, null, null, BouncyCastleProvider.PROVIDER_NAME, ldapOrder);
    }
    
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider)
            throws CertificateParsingException, OperatorCreationException {
        return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter,
                provider, true);
    }
    
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder)
            throws CertificateParsingException, OperatorCreationException {
        try {
            return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter,
                    provider, ldapOrder, null);
        } catch (CertIOException e) {
          throw new IllegalStateException("CertIOException was thrown due to an invalid extension, but no extensions were provided.", e);
        }
    }
    
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder,
            List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
        // Create self signed certificate
        Date firstDate = new Date();

        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));

        Date lastDate = new Date();

        // validity in days = validity*24*60*60*1000 milliseconds
        lastDate.setTime(lastDate.getTime() + (validity * (24 * 60 * 60 * 1000)));

        return genSelfCertForPurpose(dn, firstDate, lastDate, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder, additionalExtensions);
    }
    
    public static X509Certificate genSelfCertForPurpose(String dn, Date firstDate, Date lastDate, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder,
            List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
        // Transform the PublicKey to be sure we have it in a format that the X509 certificate generator handles, it might be
        // a CVC public key that is passed as parameter
        PublicKey publicKey = null;
        if (pubKey instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pubKey;
            RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(rsapk.getModulus(), rsapk.getPublicExponent());
            try {
                publicKey = KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
            } catch (InvalidKeySpecException e) {
                log.error("Error creating RSAPublicKey from spec: ", e);
                publicKey = pubKey;
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("RSA was not a known algorithm", e);
            }
        } else if (pubKey instanceof ECPublicKey) {
            ECPublicKey ecpk = (ECPublicKey) pubKey;
            try {
                ECPublicKeySpec ecspec = new ECPublicKeySpec(ecpk.getW(), ecpk.getParams()); // will throw NPE if key is "implicitlyCA"
                final String algo = ecpk.getAlgorithm();
                if (algo.equals(AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
                    try {
                        publicKey = KeyFactory.getInstance("ECGOST3410").generatePublic(ecspec);
                    } catch (NoSuchAlgorithmException e) {
                        throw new IllegalStateException("ECGOST3410 was not a known algorithm", e);
                    }
                } else if (algo.equals(AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
                    try {
                        publicKey = KeyFactory.getInstance("DSTU4145").generatePublic(ecspec);
                    } catch (NoSuchAlgorithmException e) {
                        throw new IllegalStateException("DSTU4145 was not a known algorithm", e);
                    }
                } else {
                    try {
                        publicKey = KeyFactory.getInstance("EC").generatePublic(ecspec);
                    } catch (NoSuchAlgorithmException e) {
                        throw new IllegalStateException("EC was not a known algorithm", e);
                    }
                }
            } catch (InvalidKeySpecException e) {
                log.error("Error creating ECPublicKey from spec: ", e);
                publicKey = pubKey;
            } catch (NullPointerException e) {
                log.debug("NullPointerException, probably it is implicitlyCA generated keys: " + e.getMessage());
                publicKey = pubKey;
            }
        } else {
            log.debug("Not converting key of class. " + pubKey.getClass().getName());
            publicKey = pubKey;
        }

        // Serial number is random bits
        byte[] serno = new byte[16];
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA1PRNG was not a known algorithm", e);
        }
        random.nextBytes(serno);

        final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(stringToBcX500Name(dn, ldapOrder), new BigInteger(serno).abs(),
                firstDate, lastDate, stringToBcX500Name(dn, ldapOrder), pkinfo);

        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
        BasicConstraints bc = new BasicConstraints(isCA);
        certbuilder.addExtension(Extension.basicConstraints, true, bc);

        // Put critical KeyUsage in CA-certificates
        if (isCA || keyusage != 0) {
            X509KeyUsage ku = new X509KeyUsage(keyusage);
            certbuilder.addExtension(Extension.keyUsage, true, ku);
        }

        if ((privateKeyNotBefore != null) || (privateKeyNotAfter != null)) {
            final ASN1EncodableVector v = new ASN1EncodableVector();
            if (privateKeyNotBefore != null) {
                v.add(new DERTaggedObject(false, 0, new DERGeneralizedTime(privateKeyNotBefore)));
            }
            if (privateKeyNotAfter != null) {
                v.add(new DERTaggedObject(false, 1, new DERGeneralizedTime(privateKeyNotAfter)));
            }
            certbuilder.addExtension(Extension.privateKeyUsagePeriod, false, new DERSequence(v));
        }

        // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Firefox.
        try {
            if (isCA) {
                JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                SubjectKeyIdentifier ski = extensionUtils.createSubjectKeyIdentifier(publicKey);
                AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(publicKey);
                certbuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
                certbuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
            }
        } catch (IOException e) { // do nothing
        }

        // CertificatePolicies extension if supplied policy ID, always non-critical
        if (policyId != null) {
            PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(policyId));
            DERSequence seq = new DERSequence(pi);
            certbuilder.addExtension(Extension.certificatePolicies, false, seq);
        }
        // Add any additional
        if (additionalExtensions != null) {
            for (final Extension extension : additionalExtensions) {
                certbuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getParsedValue());
            }
        }
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(privKey), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        X509Certificate selfcert;
        try {
            selfcert = parseCertificate(BouncyCastleProvider.PROVIDER_NAME, certHolder.getEncoded()); 
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }

        return selfcert;
    } 

    public static String getPEMCertificate(Collection<X509CertificateHolder> collection) throws CertificateException {
        final byte[] b64 = getFirstCertificate(collection);
        return BEGIN_CERTIFICATE + "\n" + new String(b64) + "\n" + END_CERTIFICATE;
    }
    
    public static String getPEMCertificate(byte[] bytes) {
        final byte[] b64 = Base64.encode(bytes);
        return BEGIN_CERTIFICATE + "\n" + new String(b64) + "\n" + END_CERTIFICATE;
    }
    
    private static byte[] getFirstCertificate(Collection<X509CertificateHolder> collection) throws CertificateException {
        if (null != collection) {
            final X509CertificateHolder certholder = collection.iterator().next();
            final X509Certificate x509cert = new JcaX509CertificateConverter().getCertificate(certholder);
            return Base64.encode(x509cert.getEncoded());
        }
        return null;
    }
    
    /**
     * Returns a certificate in PEM-format.
     *
     * @param cacert a Certificate to convert to PEM
     * @return byte array containing PEM certificate
     * @throws CertificateEncodingException if an encoding error occurred
     */
    public static String getPemFromCertificate(Certificate certificate) throws CertificateEncodingException {
        byte[] enccert = certificate.getEncoded();
        byte[] b64cert = Base64.encode(enccert);
        String out = BEGIN_CERTIFICATE_WITH_NL;
        out += new String(b64cert);
        out += END_CERTIFICATE_WITH_NL;
        return out;
    }
    
    /**
     * Gets a specified part of a DN. Specifically the first occurrence it the DN contains several instances of a part (i.e. cn=x, cn=y returns x).
     * 
     * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * 
     * @return String containing dnpart or null if dnpart is not present
     */
    public static String getPartFromDN(String dn, String dnpart) {
        String part = null;
        final List<String> dnParts = getPartsFromDNInternal(dn, dnpart, true);
        if (!dnParts.isEmpty()) {
            part = dnParts.get(0);
        }
        return part;
    }
    
    /**
     * Gets a specified parts of a DN. Returns all occurrences as an ArrayList, also works if DN contains several
     * instances of a part (i.e. cn=x, cn=y returns {x, y, null}).
     * 
     * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * 
     * @return ArrayList containing dnparts or empty list if dnpart is not present
     */
    public static List<String> getPartsFromDN(String dn, String dnpart) {
        return getPartsFromDNInternal(dn, dnpart, false);
    }
    
    private static List<String> getPartsFromDNInternal(final String dn, final String dnPart, final boolean onlyReturnFirstMatch) {
        if (log.isTraceEnabled()) {
            log.trace(">getPartsFromDNInternal: dn:'" + dn + "', dnpart=" + dnPart + ", onlyReturnFirstMatch=" + onlyReturnFirstMatch);
        }
        final List<String> parts = new ArrayList<>();
        if (dn != null && dnPart != null) {
            final String dnPartLowerCase = dnPart.toLowerCase();
            final int dnPartLenght = dnPart.length();
            boolean quoted = false;
            boolean escapeNext = false;
            int currentStartPosition = -1;
            for (int i = 0; i < dn.length(); i++) {
                final char current = dn.charAt(i);
                // Toggle quoting for every non-escaped "-char
                if (!escapeNext && current == '"') {
                    quoted = !quoted;
                }
                // If there is an unescaped and unquoted =-char we need to investigate if it is a match for the sought after part
                if (!quoted && !escapeNext && current == '=' && dnPartLenght <= i) {
                    // Check that the character before our expected partName isn't a letter (e.g. dnsName=.. should not match E=..)
                    if (i - dnPartLenght - 1 < 0 || !Character.isLetter(dn.charAt(i - dnPartLenght - 1))) {
                        boolean match = true;
                        for (int j = 0; j < dnPartLenght; j++) {
                            if (Character.toLowerCase(dn.charAt(i - dnPartLenght + j)) != dnPartLowerCase.charAt(j)) {
                                match = false;
                                break;
                            }
                        }
                        if (match) {
                            currentStartPosition = i + 1;
                        }
                    }
                }
                // When we have found a start marker, we need to be on the lookout for the ending marker
                if (currentStartPosition != -1 && ((!quoted && !escapeNext && (current == ',' || current == '+')) || i == dn.length() - 1)) {
                    int endPosition = (i == dn.length() - 1) ? dn.length() - 1 : i - 1;
                    // Remove white spaces from the end of the value
                    while (endPosition > currentStartPosition && dn.charAt(endPosition) == ' ') {
                        endPosition--;
                    }
                    // Remove white spaces from the beginning of the value
                    while (endPosition > currentStartPosition && dn.charAt(currentStartPosition) == ' ') {
                        currentStartPosition++;
                    }
                    // Only return the inner value if the part is quoted
                    if (currentStartPosition != dn.length() && dn.charAt(currentStartPosition) == '"' && dn.charAt(endPosition) == '"') {
                        currentStartPosition++;
                        endPosition--;
                    }
                    parts.add(unescapeFieldValue(dn.substring(currentStartPosition, endPosition + 1)));
                    if (onlyReturnFirstMatch) {
                        break;
                    }
                    currentStartPosition = -1;
                }
                if (escapeNext) {
                    // This character was escaped, so don't escape the next one
                    escapeNext = false;
                } else {
                    if (!quoted && current == '\\') {
                        // This escape character is not escaped itself, so the next one should be
                        escapeNext = true;
                    }
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getPartsFromDNInternal: resulting DN part=" + parts.toString());
        }
        return parts;
    }
    
    /**
     * Unescapes a value of a field in a DN, SAN or directory attributes.
     * Unlike LDAPDN.unescapeRDN, this method handles value without the field name (e.g. example.com) and empty values (e.g. DNSNAME=)
     * @param value Value to unescape
     * @return Unescaped string
     */
    protected static String unescapeFieldValue(final String value) {
        if (value == null) {
            return null;
        } else {
            return UNESCAPE_FIELD_REGEX.matcher(value).replaceAll("$1");
        }
    }
    
    /**
     * Obtains a List with the ASN1ObjectIdentifiers for dNObjects names, in the specified pre-defined order
     * 
     * @param ldaporder if true the returned order are as defined in LDAP RFC (CN=foo,O=bar,C=SE), otherwise the order is a defined in X.500
     *            (C=SE,O=bar,CN=foo).
     * @return a List with ASN1ObjectIdentifiers defining the known order we require
     * @see org.cesecore.certificates.util.DnComponents#getDnObjects(boolean)
     */
    private static List<ASN1ObjectIdentifier> getX509FieldOrder(boolean ldaporder) {
        return getX509FieldOrder(DnComponents.getDnObjects(ldaporder));
    }
    
    /**
     * Obtains a List with the ASN1ObjectIdentifiers for dNObjects names, in the specified order
     * 
     * @param order an array of DN objects.
     * @return a List with ASN1ObjectIdentifiers defining the known order we require
     * @see org.cesecore.certificates.util.DnComponents#getDnObjects(boolean) for definition of the contents of the input array
     */
    private static List<ASN1ObjectIdentifier> getX509FieldOrder(String[] order) {
        List<ASN1ObjectIdentifier> fieldOrder = new ArrayList<>();
        for (final String dNObject : order) {
            fieldOrder.add(DnComponents.getOid(dNObject));
        }
        return fieldOrder;
    }

    
  

   
    
    /**
     * Obtain a X500Name reordered, if some fields from original X500Name doesn't appear in "ordering" parameter, they will be added at end in the
     * original order.
     * 
     * @param x500Name the X500Name that is unordered
     * @param ldaporder true if LDAP ordering of DN should be used (default in EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
     *            order is the reverse
     * @param order specified order, which overrides 'ldaporder', care must be taken constructing this String array, ignored if null or empty
     * @param applyLdapToCustomOrder specifies if the ldaporder setting should apply to an order (custom order) if this is not empty
     * @param nameStyle Controls how the name is encoded. Usually it should be a CeSecoreNameStyle.
     * @return X500Name with ordered components according to the ordering vector
     */
    private static X500Name getOrderedX500Name(final X500Name x500Name, boolean ldaporder, String[] order, final boolean applyLdapToCustomOrder, final X500NameStyle nameStyle) {        
        // Guess order of the input name
        final boolean isLdapOrder = !isDNReversed(x500Name.toString());
        // If we think the DN is in LDAP order, first order it as a LDAP DN, if we don't think it's LDAP order
        // order it as a X.500 DN. If we haven't specified our own ordering
        final List<ASN1ObjectIdentifier> ordering;
        final boolean useCustomOrder = (order != null) && (order.length > 0);  
        if (useCustomOrder) {
            log.debug("Using custom DN order");
            ordering = getX509FieldOrder(order);            
        } else {
            ordering = getX509FieldOrder(isLdapOrder);
        }
        
        // -- New order for the X509 Fields
        final List<ASN1ObjectIdentifier> newOrdering = new ArrayList<>();
        final List<RDN> newValues = new ArrayList<>();
        // -- Add ordered fields
        final RDN[] allRdns= x500Name.getRDNs();

        final HashSet<ASN1ObjectIdentifier> hs = new HashSet<>(allRdns.length + ordering.size());
        for (final ASN1ObjectIdentifier oid : ordering) {
            if (!hs.contains(oid)) {
                hs.add(oid);
                // We can't use x500Name.getRDNs(oid) because it will also hunt inside multi valued RNDs
                //final RDN[] valueList = x500Name.getRDNs(oid);
                // -- Only add the OID if has not null value
                for (final RDN value : allRdns) {
                    if (oid.equals(value.getFirst().getType())) {
                        newOrdering.add(oid);
                        newValues.add(value);
                    }
                }
            }
        }
        // -- Add unexpected fields to the end
        for (final RDN rdn : allRdns) {
            final ASN1ObjectIdentifier oid = rdn.getFirst().getType();
            if (!hs.contains(oid)) {
                hs.add(oid);
                final RDN[] valueList = x500Name.getRDNs(oid);
                // -- Only add the OID if has not null value
                for (final RDN value : valueList) {
                    newOrdering.add(oid);
                    newValues.add(value);
                    if (log.isDebugEnabled()) {
                        log.debug("added --> " + oid + " val: " + value);
                    }
                }
            }
        }
        // If the requested ordering was the reverse of the ordering the input string was in (by our guess in the beginning)
        // we have to reverse the vectors.
        // Unless we have specified a custom order, and choose to not apply LDAP Order to this custom order, in which case we will not change the order from the custom
        if ( (useCustomOrder && applyLdapToCustomOrder) || !useCustomOrder) {
            if (ldaporder != isLdapOrder) {
                if (log.isDebugEnabled()) {
                    log.debug("Reversing order of DN, ldaporder=" + ldaporder + ", isLdapOrder=" + isLdapOrder);
                }
                Collections.reverse(newOrdering);
                Collections.reverse(newValues);
            }
        }

        X500NameBuilder nameBuilder = new X500NameBuilder(nameStyle);
        for (int i = 0; i < newOrdering.size(); i++) {
            RDN rdn = newValues.get(i);
            if (rdn.isMultiValued()) {
                AttributeTypeAndValue avas[] = rdn.getTypesAndValues();
                if (log.isDebugEnabled()) {
                    log.debug("Multi-value RDN with "+avas.length+" number of values in it.");
                }
                nameBuilder.addMultiValuedRDN(avas);
            } else {
                nameBuilder.addRDN(newOrdering.get(i), rdn.getFirst().getValue());
            }
        }
        // -- Return X500Name with the ordered fields
        return nameBuilder.build();
    } 
    
    /**
     * Escapes a value of a field in a DN, SAN or directory attributes.
     * Unlike LDAPDN.escapeRDN, this method allows empty values (e.g. DNSNAME=)
     * @param value Value to escape, with or without the XX=
     * @return Escaped string
     */
    protected static String escapeFieldValue(final String value) {
        if (value == null) {
            return null;
        } else if (value.indexOf('=') == value.length()-1) {
            return value;
        } else {
            return LDAPDN.escapeRDN(value);
        }
    }
    
    /** Returns a CertificateFactory that can be used to create certificates from byte arrays and such.
     * @param provider Security provider that should be used to create certificates, default BC is null is passed.
     * @return CertificateFactory
     */
    public static CertificateFactory getCertificateFactory(final String provider) {
        final String prov;
        if (provider == null) {
            prov = BouncyCastleProvider.PROVIDER_NAME;
        } else {
            prov = provider;
        }
        try {
            return CertificateFactory.getInstance("X.509", prov);
        } catch (NoSuchProviderException nspe) {
            log.error("NoSuchProvider: ", nspe);
        } catch (CertificateException ce) {
            log.error("CertificateException: ", ce);
        }
        return null;
    }
    
   
    /**
     * Gets an altName string from an X509Extension
     * 
     * @param ext X509Extension with AlternativeNames
     * @return String as defined in method getSubjectAlternativeName
     */
    public static String getAltNameStringFromExtension(Extension ext) {
        String altName = null;
        // GeneralNames, the actual encoded name
        GeneralNames names = getGeneralNamesFromExtension(ext);
        if (names != null) {
            try {
                GeneralName[] gns = names.getNames();
                for (GeneralName gn : gns) {
                    int tag = gn.getTagNo();
                    ASN1Encodable name = gn.getName();
                    String str = getGeneralNameString(tag, name);
                    if (str == null) {
                        continue;
                    }
                    if (altName == null) {
                        altName = escapeFieldValue(str);
                    } else {
                        altName += ", " + escapeFieldValue(str);
                    }
                }
            } catch (IOException e) {
                log.error("IOException parsing altNames: ", e);
                return null;
            }
        }
        return altName;
    }
    
    /**
     * Gets GeneralNames from an X509Extension
     * 
     * @param ext X509Extension with AlternativeNames
     * @return GeneralNames with all Alternative Names
     */
    public static GeneralNames getGeneralNamesFromExtension(Extension ext) {
        ASN1Encodable gnames = ext.getParsedValue();
        if (gnames != null) {
                GeneralNames names = GeneralNames.getInstance(gnames);
                return names;
        }
        return null;
    }
    
    private static ASN1Sequence getAltnameSequence(List<?> listitem) {
        Integer no = (Integer) listitem.get(0);
        if (no == 0) {
            byte[] altName = (byte[]) listitem.get(1);
            return getAltnameSequence(altName);
        }
        return null;
    }

    private static ASN1Sequence getAltnameSequence(byte[] value) {
        ASN1Primitive oct = null;
        try {
            oct = ASN1Primitive.fromByteArray(value);
        } catch (IOException e) {
            throw new RuntimeException("Could not read ASN1InputStream", e);
        }
        if (oct instanceof ASN1TaggedObject) {
            oct = ((ASN1TaggedObject) oct).getObject();
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(oct);
        return seq;
    }
    
    /**
     * Helper method to get MS GUID from GeneralName otherName sequence
     * 
     * @param seq the OtherName sequence
     */
    private static String getGUIDStringFromSequence(ASN1Sequence seq) {
        String ret = null;
        if (seq != null) {
            // First in sequence is the object identifier, that we must check
            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            if (id.getId().equals(GUID_OBJECTID)) {
                ASN1TaggedObject oobj = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                // Due to bug in java cert.getSubjectAltName regarding OtherName, it can be tagged an extra time...
                ASN1Primitive obj = oobj.getObject();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                ASN1OctetString str = ASN1OctetString.getInstance(obj);
                ret = new String(Hex.encode(str.getOctets()));
            }
        }
        return ret;
    }
    
    /**
     * Helper method for the above method.
     * 
     * @param seq the OtherName sequence
     * @return String which is the decoded ASN.1 UTF8 String of the (simple) OtherName
     */
    private static String getUTF8StringFromSequence(final ASN1Sequence seq, final String oid) {
        if (seq != null) {
            // First in sequence is the object identifier, that we must check
            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            if (id.getId().equals(oid)) {
                ASN1TaggedObject oobj = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                // Due to bug in java cert.getSubjectAltName regarding OtherName, it can be tagged an extra time...
                ASN1Primitive obj = oobj.getObject();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                ASN1UTF8String str = ASN1UTF8String.getInstance(obj);
                return str.getString();
            }
        }
        return null;
    }

    /**
     * Helper method.
     * 
     * @param seq the OtherName sequence
     * @return String which is the decoded ASN.1 IA5String of the (simple) OtherName
     */
    private static String getIA5StringFromSequence(final ASN1Sequence seq, final String oid) {
        if (seq != null) {
            // First in sequence is the object identifier, that we must check
            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            if (id.getId().equals(oid)) {
                ASN1TaggedObject oobj = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                // Due to bug in java cert.getSubjectAltName regarding OtherName, it can be tagged an extra time...
                ASN1Primitive obj = oobj.getObject();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                ASN1IA5String str = ASN1IA5String.getInstance(obj);
                return str.getString();
            }
        }
        return null;
    }

    /**
     * Helper method.
     * 
     * @param seq the OtherName sequence
     * @return bytes which is the decoded ASN.1 Octet String of the (simple) OtherName
     */
    private static byte[] getOctetStringFromSequence(final ASN1Sequence seq, final String oid) {
        if (seq != null) {
            // First in sequence is the object identifier, that we must check
            ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            if (id.getId().equals(oid)) {
                ASN1TaggedObject oobj = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                // Due to bug in java cert.getSubjectAltName regarding OtherName, it can be tagged an extra time...
                ASN1Primitive obj = oobj.getObject();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                ASN1OctetString str = ASN1OctetString.getInstance(obj);
                return str.getOctets();
            }
        }
        return null;
    }
    
    private static String escapePermanentIdentifierValue(String realValue) {
        return realValue.replace(PERMANENTIDENTIFIER_SEP, "\\" + PERMANENTIDENTIFIER_SEP);
    }

    private static String unescapePermanentIdentifierValue(String escapedValue) {
        return escapedValue.replace("\\" + PERMANENTIDENTIFIER, PERMANENTIDENTIFIER);
    }
    
}
