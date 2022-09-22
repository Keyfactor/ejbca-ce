/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509NameTokenizer;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.CVCAuthorizationTemplate;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.OIDField;
import org.ejbca.cvc.ReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

import com.keyfactor.util.certificates.CertificateToolsBase;
import com.keyfactor.util.certificates.CrlTools;
import com.keyfactor.util.certificates.X509CertificateTools;

/**
 * Tools to handle common certificate operations.
 */
public abstract class CertTools {
    private static final Logger log = Logger.getLogger(CertTools.class);

    private static final InternalResources intres = InternalResources.getInstance();

    // Initialize dnComponents
    static {
        DnComponents.getDnObjects(true);
    }

    
    /** ObjectID for Microsoft Encrypted File System Certificates extended key usage */
    public static final String EFS_OBJECTID = "1.3.6.1.4.1.311.10.3.4";
    /** ObjectID for Microsoft Encrypted File System Recovery Certificates extended key usage */
    public static final String EFSR_OBJECTID = "1.3.6.1.4.1.311.10.3.4.1";
    /** ObjectID for Microsoft Signer of documents extended key usage */
    public static final String MS_DOCUMENT_SIGNING_OBJECTID = "1.3.6.1.4.1.311.10.3.12";
    
    public static final String PRECERT_POISON_EXTENSION_OID = "1.3.6.1.4.1.11129.2.4.3";
    /** Object id id-pkix */
    public static final String id_pkix = "1.3.6.1.5.5.7";
    /** Object id id-kp */
    public static final String id_kp = id_pkix + ".3";
    /** Object id id-pda */
    public static final String id_pda = id_pkix + ".9";
    /**
     * Object id id-pda-dateOfBirth DateOfBirth ::= GeneralizedTime
     */
    public static final String id_pda_dateOfBirth = id_pda + ".1";
    /**
     * Object id id-pda-placeOfBirth PlaceOfBirth ::= DirectoryString
     */
    public static final String id_pda_placeOfBirth = id_pda + ".2";
    /**
     * Object id id-pda-gender Gender ::= PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
     */
    public static final String id_pda_gender = id_pda + ".3";
    /**
     * Object id id-pda-countryOfCitizenship CountryOfCitizenship ::= PrintableString (SIZE (2)) -- ISO 3166 Country Code
     */
    public static final String id_pda_countryOfCitizenship = id_pda + ".4";
    /**
     * Object id id-pda-countryOfResidence CountryOfResidence ::= PrintableString (SIZE (2)) -- ISO 3166 Country Code
     */
    public static final String id_pda_countryOfResidence = id_pda + ".5";
    /** OID used for creating MS Templates certificate extension */
    public static final String OID_MSTEMPLATE = "1.3.6.1.4.1.311.20.2";
    /** OID used for creating Microsoft szOID_NTDS_CA_SECURITY_EXT for ADCS vuln. CVE-2022-26931 */
    public static final String OID_MS_SZ_OID_NTDS_CA_SEC_EXT = "1.3.6.1.4.1.311.25.2";
    /** extended key usage OID Intel AMT (out of band) network management */
    public static final String Intel_amt = "2.16.840.1.113741.1.2.3";
    
    /** Object ID for CT (Certificate Transparency) specific extensions */
    public static final String id_ct_redacted_domains = "1.3.6.1.4.1.11129.2.4.6";

    public static final String BEGIN_CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String END_CERTIFICATE_REQUEST = "-----END CERTIFICATE REQUEST-----";
    public static final String BEGIN_KEYTOOL_CERTIFICATE_REQUEST = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String END_KEYTOOL_CERTIFICATE_REQUEST = "-----END NEW CERTIFICATE REQUEST-----";
   

    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";  
    public static final  String BEGIN_PKCS7  = "-----BEGIN PKCS7-----";
    public static final  String END_PKCS7     = "-----END PKCS7-----";

    /**
     * See stringToBcX500Name(String, X500NameStyle, boolean), this method uses the default name style (CeSecoreNameStyle) and ldap
     * order
     * 
     * @see #stringToBcX500Name(String, X500NameStyle, boolean)
     * @param dn String containing DN that will be transformed into X500Name, The DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
     *            the string will be added to the end positions of OID array.
     * 
     * @return X500Name, which can be empty if dn does not contain any real DN components, or null if input is null
     *
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X500Name stringToBcX500Name(final String dn) {
        return X509CertificateTools.stringToBcX500Name(dn);
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
     *
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X500Name stringToBcX500Name(final String dn, boolean ldapOrder) {
        return X509CertificateTools.stringToBcX500Name(dn, ldapOrder);
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
     *
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X500Name stringToBcX500Name(String dn, final X500NameStyle nameStyle, final boolean ldaporder) {
        return X509CertificateTools.stringToBcX500Name(dn, nameStyle, ldaporder);
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
     *
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X500Name stringToBcX500Name(String dn, final X500NameStyle nameStyle, final boolean ldaporder, final String[] order) {
        return X509CertificateTools.stringToBcX500Name(dn, nameStyle, ldaporder, order);
    }
    
    /**
     * 
     * @param dn
     * @param nameStyle
     * @param ldaporder
     * @param order
     * @param applyLdapToCustomOrder
     * @return
     *
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X500Name stringToBcX500Name(String dn, final X500NameStyle nameStyle, final boolean ldaporder, final String[] order, final boolean applyLdapToCustomOrder) {
        return X509CertificateTools.stringToBcX500Name(dn, nameStyle, ldaporder, order, applyLdapToCustomOrder);
    }

    /**
     * @deprecated User the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X500Name stringToUnorderedX500Name(String dn, final X500NameStyle nameStyle) {
        return X509CertificateTools.stringToUnorderedX500Name(dn, nameStyle);
    }

    /**
     * Every DN-string should look the same. Creates a name string ordered and looking like we want it...
     * 
     * @param dn String containing DN
     * 
     * @return String containing DN, or empty string if dn does not contain any real DN components, or null if input is null
     * 
     * @deprecated Use equivalent method from {@link X509CertificateTools}
     */
    public static String stringToBCDNString(String dn) {
        return X509CertificateTools.stringToBCDNString(dn);
    }

    /**
     * Convenience method for getting an email addresses from a DN. Uses {@link #getPartsFromDN(String,String)} internally, and searches for
     * {@link #EMAIL}, {@link #EMAIL1}, {@link #EMAIL2}, {@link #EMAIL3} and returns the first one found.
     * 
     * @param dn the DN
     * 
     * @return List containing email or empty list if email is not present
     * 
     * @deprecated Use equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static List<String> getEmailFromDN(String dn) {
        return X509CertificateTools.getEmailFromDN(dn);
    }

    /**
     * Search for e-mail address, first in SubjectAltName (as in PKIX recommendation) then in subject DN. Original author: Marco Ferrante, (c) 2005
     * CSITA - University of Genoa (Italy)
     * 
     * @param certificate
     * @return subject email or null if not present in certificate
     * 
     * @deprecated Use equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getEMailAddress(Certificate certificate) {
        log.debug("Searching for EMail Address in SubjectAltName");
        if (certificate == null) {
            return null;
        }
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) certificate;
            return X509CertificateTools.getEMailAddress(x509cert);
        }
        return null;
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
     * 
     * @deprecated Use equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static boolean isDNReversed(String dn) {       
        return X509CertificateTools.isDNReversed(dn);
    } 
  
    /**
     * Gets a specified part of a DN. Specifically the first occurrence it the DN contains several instances of a part (i.e. cn=x, cn=y returns x).
     * 
     * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * 
     * @return String containing dnpart or null if dnpart is not present
     * 
     * @deprecated Use equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getPartFromDN(String dn, String dnpart) {
        return X509CertificateTools.getPartFromDN(dn, dnpart);
    }

    /**
     * Gets a specified parts of a DN. Returns all occurrences as an ArrayList, also works if DN contains several
     * instances of a part (i.e. cn=x, cn=y returns {x, y, null}).
     * 
     * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
     * 
     * @return ArrayList containing dnparts or empty list if dnpart is not present
     * 
     * @deprecated Use equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static List<String> getPartsFromDN(String dn, String dnpart) {
        return X509CertificateTools.getPartsFromDN(dn, dnpart);
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
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static List<String> getCustomOids(String dn) {
        return X509CertificateTools.getCustomOids(dn);
    }

    /**
     * Gets subject DN in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param cert Certificate
     * 
     * @return String containing the subjects DN.
     */
    public static String getSubjectDN(final Certificate cert) {
        if (cert == null || StringUtils.equals(cert.getType(), SshCertificate.CERTIFICATE_TYPE)) {
            return "";
        } else {
            return getDN(cert, 1);
        }
    }

    /**
     * @param value String to enescape
     * @return value in unescaped RDN format
     */
    public static String getUnescapedRdnValue(final String value){
        if (StringUtils.isNotEmpty(value)) {
            return org.ietf.ldap.LDAPDN.unescapeRDN(value);
        } else {
            return value;
        }
    }

    /**
     * Gets issuer DN in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param cert Certificate
     * 
     * @return String containing the issuers DN, or null if cert is null.
     */
    public static String getIssuerDN(final Certificate cert) {
        if (cert != null && StringUtils.equals(cert.getType(), SshCertificate.CERTIFICATE_TYPE)) {
            SshCertificate sshCertificate = (SshCertificate) cert;
            return sshCertificate.getIssuerIdentifier();
        } else {
            return getDN(cert, 2);
        }
    }

    /**
     * Gets subject or issuer DN in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param cert a Certificate
     * @param which 1 = subjectDN, anything else = issuerDN
     * 
     * @return String containing the DN, or null if cert is null.
     */
    private static String getDN(final Certificate cert, final int which) {
        String ret = null;
        if (cert == null) {
            return null;
        }
        if (cert instanceof X509Certificate) {
            return X509CertificateTools.getDN(cert, which);
        } else if (StringUtils.equals(cert.getType(), "CVC")) {
            final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
            try {
                ReferenceField rf = null;
                if (which == 1) {
                    rf = cvccert.getCVCertificate().getCertificateBody().getHolderReference();
                } else {
                    rf = cvccert.getCVCertificate().getCertificateBody().getAuthorityReference();
                }
                if (rf != null) {
                    // Construct a "fake" DN which can be used in EJBCA
                    // Use only mnemonic and country, since sequence is more of a serialnumber than a DN part
                    String dn = "";
                    if (rf.getMnemonic() != null) {
                        if (StringUtils.isNotEmpty(dn)) {
                            dn += ", ";
                        }
                        dn += "CN=" + rf.getMnemonic();
                    }
                    if (rf.getCountry() != null) {
                        if (StringUtils.isNotEmpty(dn)) {
                            dn += ", ";
                        }
                        dn += "C=" + rf.getCountry();
                    }
                    ret = stringToBCDNString(dn);
                }
            } catch (NoSuchFieldException e) {
                log.error("NoSuchFieldException: ", e);
                return null;
            }
        }
        return ret;
    }

    /**
     * Gets Serial number of the certificate.
     * 
     * @param cert Certificate
     * 
     * @return BigInteger containing the certificate serial number. Can be 0 for CVC certificates with alphanumeric serial numbers if the sequence
     *         does not contain any number characters at all.
     * @throws IllegalArgumentException if null input of certificate type is not handled
     */
    public static BigInteger getSerialNumber(Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("Null input");
        }
        BigInteger ret = null;
        if (cert instanceof X509Certificate) {
            X509Certificate xcert = (X509Certificate) cert;
            ret = X509CertificateTools.getSerialNumber(xcert);
        } else if (StringUtils.equals(cert.getType(), "CVC")) {
            // For CVC certificates the sequence field of the HolderReference is kind of a serial number,
            // but if can be alphanumeric which means it can not be made into a BigInteger
            CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
            try {
                String sequence = cvccert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
                ret = getSerialNumberFromString(sequence);
            } catch (NoSuchFieldException e) {
                log.error("getSerialNumber: NoSuchFieldException: ", e);
                ret = BigInteger.valueOf(0);
            }
        } else if (StringUtils.equals(cert.getType(), SshCertificate.CERTIFICATE_TYPE)) {
            SshCertificate sshCertificate = (SshCertificate) cert;
            ret = new BigInteger(sshCertificate.getSerialNumberAsString());
        } else {
            throw new IllegalArgumentException("getSerialNumber: Certificate of type " + cert.getType() + " is not implemented");
        }
        return ret;
    }

    /**
     * Gets a serial number in numeric form, it takes - either a hex encoded integer with length != 5 (x.509 certificate) - 5 letter numeric string
     * (cvc), will convert the number to an int - 5 letter alfanumeric string vi some numbers in it (cvc), will convert the numbers in it to a numeric
     * string (remove the letters) and convert to int - 5 letter alfanumeric string with only letters (cvc), will convert to integer from string with
     * radix 36
     * 
     * @param sernoString
     * @return BigInteger
     * 
     * @deprecated Use the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static BigInteger getSerialNumberFromString(String sernoString) {      
        return X509CertificateTools.getSerialNumberFromString(sernoString);
    }

    /**
     * Gets Serial number of the certificate as a string. For X509 Certificate this means a HEX encoded BigInteger, and for CVC certificate is means
     * the sequence field of the holder reference.
     * <p>
     * For X509 certificates, the value is normalized (uppercase without leading zeros), so there's no need to normalize the returned value.
     * 
     * @param cert Certificate
     * 
     * @return String to be displayed or used in RoleMember objects
     * @throws IllegalArgumentException if input is null or certificate type is not implemented
     */
    public static String getSerialNumberAsString(Certificate cert) {
        String ret = null;
        if (cert == null) {
            throw new IllegalArgumentException("getSerialNumber: cert is null");
        }
        if (cert instanceof X509Certificate) {
            X509Certificate xcert = (X509Certificate) cert;
            ret = X509CertificateTools.getSerialNumberAsString(xcert);
        } else if (StringUtils.equals(cert.getType(), "CVC")) {
            // For CVC certificates the sequence field of the HolderReference is kind of a serial number,
            // but if can be alphanumeric which means it can not be made into a BigInteger
            CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
            try {
                ret = cvccert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
            } catch (NoSuchFieldException e) {
                log.error("getSerialNumber: NoSuchFieldException: ", e);
                ret = "N/A";
            }
        } else if(StringUtils.equals(cert.getType(), SshCertificate.CERTIFICATE_TYPE)) {
            SshCertificate sshCertificate = (SshCertificate) cert;
            ret = sshCertificate.getSerialNumberAsString();           
        } else {
            throw new IllegalArgumentException("getSerialNumber: Certificate of type " + cert.getType() + " is not implemented");
        }
        return ret;
    }

    /**
     * Gets the signature value (the raw signature bits) from the certificate. For an X509 certificate this is the ASN.1 definition which is:
     * signature BIT STRING
     * 
     * @param cert Certificate
     * 
     * @return byte[] containing the certificate signature bits, if cert is null a byte[] of size 0 is returned.
     */
    public static byte[] getSignature(Certificate cert) {
        byte[] ret = null;
        if (cert == null) {
            ret = new byte[0];
        } else {
            if (cert instanceof X509Certificate) {
                X509Certificate xcert = (X509Certificate) cert;
                ret = xcert.getSignature();
            } else if (StringUtils.equals(cert.getType(), "CVC")) {
                CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
                try {
                    ret = cvccert.getCVCertificate().getSignature();
                } catch (NoSuchFieldException e) {
                    log.error("NoSuchFieldException: ", e);
                    return null;
                }
            } else if(StringUtils.equals(cert.getType(), SshCertificate.CERTIFICATE_TYPE)) {
                SshCertificate sshCertificate = (SshCertificate) cert;
                ret = sshCertificate.getSignature();
            }
        }
        return ret;
    }

    /**
     * Gets issuer DN for CRL in the format we are sure about (BouncyCastle),supporting UTF8.
     * 
     * @param crl X509RL
     * 
     * @return String containing the DN.
     * 
     * @deprecated Use the equivalent method in CrlTools
     */
    @Deprecated
    public static String getIssuerDN(X509CRL crl) {
        return CrlTools.getIssuerDN(crl);        
    }

    public static Date getNotBefore(Certificate cert) {
        Date ret = null;
        if (cert == null) {
            throw new IllegalArgumentException("getNotBefore: cert is null");
        }
        if (cert instanceof X509Certificate) {
            X509Certificate xcert = (X509Certificate) cert;
            ret = xcert.getNotBefore();
        } else if (StringUtils.equals(cert.getType(), "CVC")) {
            CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
            try {
                ret = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
            } catch (NoSuchFieldException e) {
                // it is not uncommon that this field is missing in CVC certificate requests (it's not in the EAC standard so)
                log.debug("NoSuchFieldException: " + e.getMessage());
                return null;
            }
        }
        return ret;
    }

    public static Date getNotAfter(Certificate cert) {
        Date ret = null;
        if (cert == null) {
            throw new IllegalArgumentException("getNotAfter: cert is null");
        }
        if (cert instanceof X509Certificate) {
            final X509Certificate xcert = (X509Certificate) cert;
            ret = xcert.getNotAfter();
        } else if (StringUtils.equals(cert.getType(), "CVC")) {
            final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
            try {
                ret = cvccert.getCVCertificate().getCertificateBody().getValidTo();
            } catch (NoSuchFieldException e) {
                // it is not uncommon that this field is missing in CVC certificate requests (it's not in the EAC standard so)
                if (log.isDebugEnabled()) {
                    log.debug("NoSuchFieldException: " + e.getMessage());
                }
                return null;
            }
        }
        return ret;
    }



    public static CertificateFactory getCertificateFactory() {
        return X509CertificateTools.getCertificateFactory(BouncyCastleProvider.PROVIDER_NAME);
    }

   /**
    * Reads certificates in PEM-format from a filename.
    * The stream may contain other things between the different certificates.
    * 
    * @param certFilename filename of the file containing the certificates in PEM-format
    * @return Ordered List of Certificates, first certificate first, or empty List
    * @throws FileNotFoundException if certFile was not found
    * @throws CertificateParsingException if the file contains an incorrect certificate.
    * 
    * @deprecated Use org.cesecore.util.CertTools.getCertsFromPEM(String, Class<T>) instead
    */
    @Deprecated
   public static List<Certificate> getCertsFromPEM(String certFilename) throws FileNotFoundException, CertificateParsingException {
        return getCertsFromPEM(certFilename, Certificate.class);
    }
    
    /**
     * Reads certificates in PEM-format from a filename.
     * The stream may contain other things between the different certificates.
     * 
     * @param certFilename filename of the file containing the certificates in PEM-format
     * @param returnType a Class specifying the desired return type. Certificate can be used if return type is unknown.
     * 
     * @return Ordered List of Certificates, first certificate first, or empty List
     * @throws FileNotFoundException if certFile was not found
     * @throws CertificateParsingException if the file contains an incorrect certificate.
     */
    public static <T extends Certificate> List<T> getCertsFromPEM(String certFilename, Class<T> returnType) throws FileNotFoundException, CertificateParsingException {
        if (log.isTraceEnabled()) {
            log.trace(">getCertfromPEM: certFilename=" + certFilename);
        }
        final List<T> certs;
        try (final InputStream inStrm = new FileInputStream(certFilename)) {
            certs = getCertsFromPEM(inStrm, returnType);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to close input stream");
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertfromPEM: certFile=" + certFilename);
        }
        return certs;
    }
    
    /**
     * Reads a CA certificate and its certificate chain by a file. If it is a chain it is a file with multiple PEM encoded certificates.
     * A single certificate is either in PEM or binary format.
     *  
     * @param file the full path of the file.
     * @return a byte array containing one PEM or binary certificate, or all certificates in the chain in PEM format. First is the CA certificate, followed by its certificate chain.
     * @throws FileNotFoundException if the file cannot be found.
     * @throws CertificateParsingException if a certificate could not be parsed.
     * @throws CertificateEncodingException if a certificate cannot be encoded.
     */
    public static final byte[] readCertificateChainAsArrayOrThrow(final String file)
            throws FileNotFoundException, IOException, CertificateParsingException, CertificateEncodingException {
        
        final List<byte[]> cachain = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            Collection<Certificate> certs = CertTools.getCertsFromPEM(fis, Certificate.class);
            Iterator<Certificate> iter = certs.iterator();
            while (iter.hasNext()) {
                Certificate cert = iter.next();
                cachain.add(cert.getEncoded());
            }
        } catch (CertificateParsingException e) {
            // It was perhaps not a PEM chain...see if it was a single binary certificate
            byte[] certbytes = FileTools.readFiletoBuffer(file);
            Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class); // check if it is a good cert, decode PEM if it is PEM, etc
            cachain.add(cert.getEncoded());
        }
        
        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            for (byte[] bytes : cachain) {
                bos.write(bytes);
            }
            final byte[] result = bos.toByteArray();
            return result;
        }
    }
    
    public static final List<CertificateWrapper> bytesToListOfCertificateWrapperOrThrow(final byte[] bytes) throws CertificateParsingException {
        Collection<java.security.cert.Certificate> certs = null;
        try {
            certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(bytes), java.security.cert.Certificate.class);
        } catch (CertificateException e) {
            log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
            // See if it is a single binary certificate
            java.security.cert.Certificate cert = CertTools.getCertfromByteArray(bytes, java.security.cert.Certificate.class);
            certs = new ArrayList<>();
            certs.add(cert);
        }
        return EJBTools.wrapCertCollection(certs);
    }

    /**
     * Reads certificates in PEM-format from an InputStream. 
     * The stream may contain other things between the different certificates.
     * 
     * @param certstream the input stream containing the certificates in PEM-format
     * @return Ordered List of Certificates, first certificate first, or empty List
     *
     * @throws CertificateParsingException if the stream contains an incorrect certificate.
     * 
     * @deprecated Use org.cesecore.util.CertTools.getCertsFromPEM(InputStream, Class<T>) instead. 
     */
    @Deprecated
    public static List<Certificate> getCertsFromPEM(InputStream certstream) throws CertificateParsingException {
        return getCertsFromPEM(certstream, Certificate.class);
    }
    
    /**
     * Reads certificates in PEM-format from an InputStream. 
     * The stream may contain other things between the different certificates.
     * 
     * @param certstream the input stream containing the certificates in PEM-format
     * @param returnType specifies the desired certificate type. Certificate can be used if certificate type is unknown.
     * @return Ordered List of Certificates, first certificate first, or empty List
     * @exception CertificateParsingException if the stream contains an incorrect certificate.
     */
    public static <T extends Certificate> List<T> getCertsFromPEM(InputStream certstream, Class<T> returnType) throws CertificateParsingException {
        if (log.isTraceEnabled()) {
            log.trace(">getCertfromPEM");
        }
        final ArrayList<T> ret = new ArrayList<>();
        String beginKeyTrust = "-----BEGIN TRUSTED CERTIFICATE-----";
        String endKeyTrust = "-----END TRUSTED CERTIFICATE-----";
        try (final BufferedReader bufRdr = new BufferedReader(new InputStreamReader(new SecurityFilterInputStream(certstream)))) {
            while (bufRdr.ready()) {
                final ByteArrayOutputStream ostr = new ByteArrayOutputStream();
                final PrintStream opstr = new PrintStream(ostr);
                String temp;
                while ((temp = bufRdr.readLine()) != null && !(temp.equals(X509CertificateTools.BEGIN_CERTIFICATE) || temp.equals(beginKeyTrust))) {
                    continue;
                }
                if (temp == null) {
                    if (ret.isEmpty()) {
                        // There was no certificate in the file
                        throw new CertificateParsingException("Error in " + certstream.toString() + ", missing " + X509CertificateTools.BEGIN_CERTIFICATE
                                + " boundary");
                    } else {
                        // There were certificates, but some blank lines or something in the end
                        // anyhow, the file has ended so we can break here.
                        break;
                    }
                }
                while ((temp = bufRdr.readLine()) != null && !(temp.equals(X509CertificateTools.END_CERTIFICATE) || temp.equals(endKeyTrust))) {
                    opstr.print(temp);
                }
                if (temp == null) {
                    throw new IllegalArgumentException("Error in " + certstream.toString() + ", missing " + X509CertificateTools.END_CERTIFICATE
                            + " boundary");
                }
                opstr.close();

                byte[] certbuf = Base64.decode(ostr.toByteArray());
                ostr.close();
                // Phweeew, were done, now decode the cert from file back to Certificate object
                T cert = getCertfromByteArray(certbuf, returnType);
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
     * Converts a regular array of certificates into an ArrayList, using the provided provided.
     * 
     * @param certs Certificate[] of certificates to convert
     * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
     * @return An ArrayList of certificates in the same order as the passed in array
     * @throws NoSuchProviderException
     * @throws CertificateException
     */
    public static List<Certificate> getCertCollectionFromArray(Certificate[] certs, String provider) throws CertificateException,
            NoSuchProviderException {
        if (log.isTraceEnabled()) {
            log.trace(">getCertCollectionFromArray: " + provider);
        }
        List<Certificate> ret = new ArrayList<>();
        String prov = provider;
        if (prov == null) {
            prov = BouncyCastleProvider.PROVIDER_NAME;
        }
        for (int i = 0; i < certs.length; i++) {
            Certificate cert = certs[i];
            Certificate newcert = getCertfromByteArray(cert.getEncoded(), prov);
            ret.add(newcert);
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertCollectionFromArray: " + ret.size());
        }
        return ret;
    }

    /**
     * Returns a certificate in PEM-format.
     * 
     * @param certs Collection of Certificate to convert to PEM
     * @return byte array containing PEM certificate
     * @exception CertificateException if the stream does not contain a correct certificate.
     * 
     * @deprecated Since 6.0.0, use org.cesecore.util.CertTools.getPemFromCertificateChain(Collection<Certificate>) instead
     */
    @Deprecated
    public static byte[] getPEMFromCerts(Collection<Certificate> certs) throws CertificateException {
        return getPemFromCertificateChain(certs);
    }

    /**
     * Returns a certificate in PEM-format.
     * 
     * @param certs Collection of Certificate to convert to PEM
     * @return byte array containing PEM certificate
     * @throws CertificateEncodingException if an encoding error occurred
     * @deprecated Use the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static byte[] getPemFromCertificateChain(Collection<Certificate> certs) throws CertificateEncodingException  {
        return X509CertificateTools.getPemFromCertificateChain(certs);
    }
    /**
     * Returns a certificate in PEM-format.
     *
     * @param cacert a Certificate to convert to PEM
     * @return byte array containing PEM certificate
     * @throws CertificateEncodingException if an encoding error occurred
     * 
     * @deprecated Use the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static String getPemFromCertificate(Certificate cacert) throws CertificateEncodingException {
        return X509CertificateTools.getPemFromCertificate(cacert);
    }

    /** @return a CRL in PEM-format as a byte array. 
     *
     * @deprecated Use the equivalent method from {@link CrlTools}
     */
    public static byte[] getPEMFromCrl(byte[] crlBytes) {
        return CrlTools.getPEMFromCrl(crlBytes);
    }

    /** @return a PublicKey in PEM-format as a byte array. */
    public static byte[] getPEMFromPublicKey(final byte[] publicKeyBytes) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try ( final PrintStream printStream = new PrintStream(baos) ) {
            CertificateToolsBase.writeAsPemEncoded(printStream, publicKeyBytes, BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
        }
        return baos.toByteArray();
    }

    public static byte[] getPEMFromPrivateKey(final byte[] privateKeyBytes) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try ( final PrintStream printStream = new PrintStream(baos) ) {
            CertificateToolsBase.writeAsPemEncoded(printStream, privateKeyBytes, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
        }
        return baos.toByteArray();
    }

    /** @return a PublicKey in PEM-format as a byte array. */
    public static byte[] getPEMFromCertificateRequest(final byte[] certificateRequestBytes) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try ( final PrintStream printStream = new PrintStream(baos) ) {
            CertificateToolsBase.writeAsPemEncoded(printStream, certificateRequestBytes, BEGIN_CERTIFICATE_REQUEST, END_CERTIFICATE_REQUEST);
        }
        return baos.toByteArray();
    }
    
    /** 
     * Generates PEM from binary pkcs#7 data.
     * @param pkcs7Binary pkcs#7 binary data
     * @return a pkcs#7 PEM encoded */
    public static byte[] getPemFromPkcs7(final byte[] pkcs7Binary) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try ( final PrintStream printStream = new PrintStream(baos) ) {
            CertificateToolsBase.writeAsPemEncoded(printStream, pkcs7Binary, BEGIN_PKCS7, END_PKCS7);
        }
        return baos.toByteArray();
    }



    /**
     * Creates Certificate from byte[], can be either an X509 certificate or a CVCCertificate
     * 
     * @param cert byte array containing certificate in binary (DER) format, or PEM encoded X.509 certificate
     * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
     * 
     * @return a Certificate 
     * @throws CertificateParsingException if certificate couldn't be parsed from cert
     * 
     * @deprecated Use org.cesecore.util.CertTools.getCertfromByteArray(byte[], String, Class<T>) instead. 
     */
    @Deprecated
    public static Certificate getCertfromByteArray(byte[] cert, String provider) throws CertificateParsingException {
        return getCertfromByteArray(cert, provider, Certificate.class);
    }
    
    /**
     * Creates Certificate from byte[], can be either an X509 certificate or a CVCCertificate
     * 
     * @param cert byte array containing certificate in binary (DER) format, or PEM encoded X.509 certificate
     * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
     * @param returnType the type of Certificate to be returned. Certificate can be used if certificate type is unknown.
     * 
     * @return a Certificate 
     * @throws CertificateParsingException if certificate couldn't be parsed from cert, or if the incorrect return type was specified.
     * 
     */
    public static <T extends Certificate> T getCertfromByteArray(byte[] cert, String provider, Class<T> returnType) throws CertificateParsingException {
        String prov = provider;
        if (provider == null) {
            prov = BouncyCastleProvider.PROVIDER_NAME;
        }
        
        if(returnType.equals(X509Certificate.class)) {
            return returnType.cast(X509CertificateTools.parseCertificate(prov, cert));
        } else if (returnType.equals(CardVerifiableCertificate.class)) {
            return returnType.cast(parseCardVerifiableCertificate(cert));
        } else {
            //Let's guess...
            try {
                return returnType.cast(X509CertificateTools.parseCertificate(prov, cert));
            } catch (CertificateParsingException e) {
                try {
                    return returnType.cast(parseCardVerifiableCertificate(cert));
                } catch (CertificateParsingException e1) {
                    throw new CertificateParsingException("No certificate could be parsed from byte array. See debug logs for details.");
                }
            }
        }
    }
        
    private static CardVerifiableCertificate parseCardVerifiableCertificate(final byte[] cert) throws CertificateParsingException {
        // We could not create an X509Certificate, see if it is a CVC certificate instead
        try {
            final CVCertificate parsedObject = CertificateParser.parseCertificate(cert);
            return new CardVerifiableCertificate(parsedObject);
        } catch (ParseException e) {
            throw new CertificateParsingException("ParseException trying to read CVCCertificate.", e);
        } catch (ConstructionException e) {
            throw new CertificateParsingException("ConstructionException trying to read CVCCertificate.", e);
        } 
    }

   
    
    /**
     * 
     * @throws CertificateParsingException if the byte array does not contain a proper certificate.
     * 
     * @deprecated Use org.cesecore.util.CertTools.getCertfromByteArray(byte[], Class<T>) to specify return type instead.
     */
    @Deprecated
    public static Certificate getCertfromByteArray(byte[] cert) throws CertificateParsingException {
        return getCertfromByteArray(cert, Certificate.class);
    }
    
    /**
     * @param returnType the type of Certificate to be returned, for example X509Certificate.class. Certificate.class can be used if certificate type is unknown.
     * 
     * @throws CertificateParsingException if the byte array does not contain a proper certificate.
     */
    public static <T extends Certificate> T getCertfromByteArray(byte[] cert, Class<T> returnType) throws CertificateParsingException {
        return getCertfromByteArray(cert, BouncyCastleProvider.PROVIDER_NAME, returnType);
    }

    /**
     * Creates X509CRL from byte[].
     * 
     * @param crl byte array containing CRL in DER-format
     * 
     * @return X509CRL
     * 
     * @throws CRLException if the byte array does not contain a correct CRL.
     * 
     * @deprecated Use the equivalent method from {@link CrlTools}
     */
    @Deprecated
    public static X509CRL getCRLfromByteArray(byte[] crl) throws CRLException {
        return CrlTools.getCRLfromByteArray(crl);
    } 
    
    /**
     * Builds a standard CSR from a PKCS#10 request
     * 
     * @param pkcs10CertificationRequest a PKCS#10 request
     * @return a CSR as a string
     * 
     * @deprecated Use the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static String buildCsr(final PKCS10CertificationRequest pkcs10CertificationRequest) {
        return X509CertificateTools.buildCsr(pkcs10CertificationRequest);
    }

    /**
     * Checks if a certificate is self signed by verifying if subject and issuer are the same.
     * 
     * @param cert the certificate that shall be checked.
     * 
     * @return boolean true if the certificate has the same issuer and subject, false otherwise.
     */
    public static boolean isSelfSigned(Certificate cert) {
        if (log.isTraceEnabled()) {
            log.trace(">isSelfSigned: cert: " + CertTools.getIssuerDN(cert) + "\n" + CertTools.getSubjectDN(cert));
        }
        boolean ret = CertTools.getSubjectDN(cert).equals(CertTools.getIssuerDN(cert));
        if (log.isTraceEnabled()) {
            log.trace("<isSelfSigned:" + ret);
        }
        return ret;
    } // isSelfSigned

    /**
     * Checks if a certificate is valid.
     * @param warnIfAboutToExpire Also print a WARN log message if the certificate is about to expire. If false, it is still printed at DEBUG level. 
     * 
     * @param signerCert the certificate to be tested
     * @return true if the certificate is valid
     */
    public static boolean isCertificateValid(final X509Certificate certificate, final boolean warnIfAboutToExpire) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("certificate.errorcerthasexpired", certificate.getSerialNumber().toString(16), certificate.getIssuerDN()));
            }
            return false;
        } catch (CertificateNotYetValidException e) {
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("certificate.errornotyetvalid", certificate.getSerialNumber().toString(16), certificate.getIssuerDN()));
            }
            return false;
        }
        final long warnBeforeExpirationTime = OcspConfiguration.getWarningBeforeExpirationTime();
        if (warnBeforeExpirationTime < 1) {
            return true;
        }
        final Date warnDate = new Date(new Date().getTime() + warnBeforeExpirationTime);
        try {
            certificate.checkValidity(warnDate);
        } catch (CertificateExpiredException e) {
            if (warnIfAboutToExpire || log.isDebugEnabled()) {
                final Level logLevel = warnIfAboutToExpire ? Level.WARN : Level.DEBUG;
                log.log(logLevel, intres.getLocalizedMessage("certificate.warncertwillexpire", certificate.getSerialNumber().toString(16), certificate.getIssuerDN(),
                        certificate.getNotAfter()));
            }
        } catch (CertificateNotYetValidException e) {
            throw new IllegalStateException("This should never happen.", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Time for \"certificate will soon expire\" not yet reached. You will be warned after: "
                    + new Date(certificate.getNotAfter().getTime() - warnBeforeExpirationTime));
        }
        return true;
    }

    /**
     * Checks if a certificate is a CA certificate according to BasicConstraints (X.509), or role (CVC). If there is no basic constraints extension on
     * a X.509 certificate, false is returned.
     * 
     * @param cert the certificate that shall be checked.
     * 
     * @return boolean true if the certificate belongs to a CA.
     */
    public static boolean isCA(Certificate cert) {
        if (log.isTraceEnabled()) {
            log.trace(">isCA");
        }
        boolean ret = false;
        if (cert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) cert;
            ret = X509CertificateTools.isCA(x509cert);
        } else if (StringUtils.equals(cert.getType(), "CVC")) {
            CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
            try {
                CVCAuthorizationTemplate templ = cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate();
                AuthorizationRole role = templ.getAuthorizationField().getAuthRole();
                if (role.isCVCA() || role.isDV()) {
                    ret = true;
                }
            } catch (NoSuchFieldException e) {
                log.error("NoSuchFieldException: ", e);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<isCA:" + ret);
        }
        return ret;
    }

    /**
     * Is OCSP extended key usage set for a certificate?
     * 
     * @param cert to check.
     * @return true if the extended key usage for OCSP is check
     * 
     * @Deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static boolean isOCSPCert(X509Certificate cert) {    
        return X509CertificateTools.isOCSPCert(cert);
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
     * 
     * @Deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg,
            boolean isCA) throws OperatorCreationException, CertificateException  {
        return X509CertificateTools.genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA);
    }

    /** Generates a self signed certificate with keyUsage X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, i.e. a CA certificate
     * @throws IOException 
     * @throws OperatorCreationException 
     * @throws CertificateParsingException 
     * 
     * @Deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg,
            boolean isCA, String provider, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
        return X509CertificateTools.genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, provider, ldapOrder);
    } 

    /** Generates a self signed certificate with keyUsage X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, i.e. a CA certificate
     * 
     * @Deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X509Certificate genSelfCert(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey, String sigAlg,
            boolean isCA, String provider) throws OperatorCreationException, CertificateException {
        return X509CertificateTools.genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, provider);
    } 

    /**
     * Generate a selfsigned certiicate with possibility to specify key usage.
     * 
     * @param dn subject and issuer DN
     * @param validity in days
     * @param policyId policy string ('2.5.29.32.0') or null
     * @param privKey private key
     * @param pubKey public key
     * @param sigAlg signature algorithm, you can use one of the contants AlgorithmConstants.SIGALG_XXX
     * @param isCA boolean true or false
     * @param keyusage as defined by constants in X509KeyUsage
     * 
     * @Deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, boolean ldapOrder) throws CertificateParsingException, OperatorCreationException {
        return X509CertificateTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, ldapOrder);
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider)
            throws CertificateParsingException, OperatorCreationException {
        return X509CertificateTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider);
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder)
            throws CertificateParsingException, OperatorCreationException {
        return X509CertificateTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder);
    }

    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId, PrivateKey privKey, PublicKey pubKey,
            String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider, boolean ldapOrder,
            List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
        return X509CertificateTools.genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, privateKeyNotBefore,
                privateKeyNotAfter, provider, ldapOrder, additionalExtensions);
    }
    
    @Deprecated
    public static X509Certificate genSelfCertForPurpose(String dn, Date firstDate, Date lastDate, String policyId, PrivateKey privKey,
            PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, Date privateKeyNotBefore, Date privateKeyNotAfter, String provider,
            boolean ldapOrder, List<Extension> additionalExtensions) throws CertificateParsingException, OperatorCreationException, CertIOException {
        return X509CertificateTools.genSelfCertForPurpose(dn, firstDate, lastDate, policyId, privKey, pubKey, sigAlg, isCA, keyusage,
                privateKeyNotBefore, privateKeyNotAfter, provider, ldapOrder, additionalExtensions);
    } 

    /**
     * Get the authority key identifier from a certificate extensions
     * 
     * @param certificate certificate containing the extension
     * @return byte[] containing the authority key identifier, or null if it does not exist
     * 
     * @deprecated Use the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static byte[] getAuthorityKeyId(final Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return X509CertificateTools.getAuthorityKeyId((X509Certificate) certificate);
        }
        return null;
    }

    /**
     * Get the subject key identifier from a certificate extensions
     * 
     * @param certificate certificate containing the extension
     * @return byte[] containing the subject key identifier, or null if it does not exist
     * 
     * @deprecated Use the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static byte[] getSubjectKeyId(final Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return X509CertificateTools.getSubjectKeyId((X509Certificate) certificate);
        }
        return null;
    }

    /**
     * Get the Authority Key Identifier from CRL extensions
     * 
     * @param crl CRL containing the extension
     * @return byte[] containing the Authority key identifier, or null if it does not exist
     * 
     * @deprecated Use the equivalent method from {@link CrlTools}
     */
    @Deprecated
    public static byte[] getAuthorityKeyId(final X509CRL crl) {
        return CrlTools.getAuthorityKeyId(crl);
    }
    
    /**
     * Get a certificate policy ID from a certificate policies extension
     * 
     * @param certificate certificate containing the extension
     * @param pos position of the policy id, if several exist, the first is as pos 0
     * @return String with the certificate policy OID, or null if an id at the given position does not exist
     * @throws IOException if extension can not be parsed
     * 
     * @deprecated Use equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static String getCertificatePolicyId(Certificate certificate, int pos) throws IOException {
        if (certificate instanceof X509Certificate) {
            return X509CertificateTools.getCertificatePolicyId((X509Certificate) certificate, pos);
        }
        return null;
    }

    /**
     * Get a list of certificate policy IDs from a certificate policies extension
     * 
     * @param certificate certificate containing the extension
     * @return List of ObjectIdentifiers, or empty list if no policies exist
     * @throws IOException if extension can not be parsed
     * 
     * @deprecated Use equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static List<ASN1ObjectIdentifier> getCertificatePolicyIds(Certificate certificate) throws IOException {
        List<ASN1ObjectIdentifier> ret = new ArrayList<>();
        if ( certificate instanceof X509Certificate) {
            ret = X509CertificateTools.getCertificatePolicyIds((X509Certificate) certificate);
        }
        return ret;
    }

    /**
     * Get a list of certificate policy information from a certificate policies extension
     * 
     * @param certificate certificate containing the extension
     * @return List of PolicyInformation, or empty list if no policies exist
     * @throws IOException if extension can not be parsed
     * 
     * @deprecated Use equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static List<PolicyInformation> getCertificatePolicies(Certificate certificate) throws IOException {
        List<PolicyInformation> ret = new ArrayList<>();
        if (certificate instanceof X509Certificate) {
           ret = X509CertificateTools.getCertificatePolicies((X509Certificate) certificate);
        }
        return ret;
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
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getUPNAltName(Certificate cert) throws CertificateParsingException {
        String ret = null;
        if (cert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) cert;     
            ret = X509CertificateTools.getUPNAltName(x509cert);
        }
        return ret;
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
     * CertTools.UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
     * CertTools.XMPPADDR_OBJECTID = "1.3.6.1.5.5.7.8.5";
     * CertTools.SRVNAME_OBJECTID = "1.3.6.1.5.5.7.8.7";
     * 
     * @param cert certificate containing the extension
     * @param oid the OID of the OtherName
     * @return String with the UTF8 name or null if the altName does not exist
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getUTF8AltNameOtherName(final Certificate cert, final String oid) throws CertificateParsingException {
        String ret = null;
        if (cert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) cert;
            ret = X509CertificateTools.getUTF8AltNameOtherName(x509cert, oid);
        }
        return ret;
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
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getPermanentIdentifierAltName(Certificate cert) throws CertificateParsingException {
        String ret = null;
        if (cert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) cert;
            ret = X509CertificateTools.getPermanentIdentifierAltName(x509cert);
        }
        return ret;
    } 


    /**
     * Gets the Microsoft specific GUID altName, that is encoded as an octet string.
     * 
     * @param cert certificate containing the extension
     * @return String with the hex-encoded GUID byte array or null if the altName does not exist
     * 
     * @deprecated Use the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static String getGuidAltName(Certificate cert) throws CertificateParsingException {
        if (cert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) cert;
            return X509CertificateTools.getGuidAltName(x509cert);
        }
        return null;
    } 

  

    /**
     * Gets an altName string from an X509Extension
     * 
     * @param ext X509Extension with AlternativeNames
     * @return String as defined in method getSubjectAlternativeName
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools} instead
     */
    public static String getAltNameStringFromExtension(Extension ext) {        
        return X509CertificateTools.getAltNameStringFromExtension(ext);
    }

    /**
     * Gets GeneralNames from an X509Extension
     * 
     * @param ext X509Extension with AlternativeNames
     * @return GeneralNames with all Alternative Names
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools} instead
     */
    public static GeneralNames getGeneralNamesFromExtension(Extension ext) {
        return X509CertificateTools.getGeneralNamesFromExtension(ext);
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
     * @param certificate containing alt names
     * @return String containing altNames of form
     *         "rfc822Name=email, dNSName=hostname, uniformResourceIdentifier=uri, iPAddress=ip, upn=upn, directoryName=CN=testDirName|dir|name", permanentIdentifier=identifierValue/assigner or
     *         empty string if no altNames exist. Values in returned String is from CertTools constants. AltNames not supported are simply not shown
     *         in the resulting string.
     * @deprecated Use the equivalent method in {@link X509CertificateTools} instead
     */
    @Deprecated
    public static String getSubjectAlternativeName(Certificate certificate) {
        if (log.isTraceEnabled()) {
            log.trace(">getSubjectAlternativeName");
        }
        String result = "";
        if (certificate instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) certificate;
            result = X509CertificateTools.getSubjectAlternativeName(x509cert);
        }
        return result;
    }

    /**
     * From an altName string as defined in getSubjectAlternativeName
     * 
     * @param altName
     * @return ASN.1 GeneralNames
     * @see #getSubjectAlternativeName
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools} instead
     */
    @Deprecated
    public static GeneralNames getGeneralNamesFromAltName(final String altName) {
        return X509CertificateTools.getGeneralNamesFromAltName(altName);
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
     *
     * @deprecated Use the equivalent method in {@link X509CertificateTools} instead
     */
    @Deprecated
    public static String getGeneralNameString(int tag, ASN1Encodable value) throws IOException {
        return X509CertificateTools.getGeneralNameString(tag, value);
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
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain, Date date, PKIXCertPathChecker... pkixCertPathCheckers)
            throws CertPathValidatorException {
        return X509CertificateTools.verify(certificate, caCertChain, date, pkixCertPathCheckers);
    }
    
    /**
     * Check the certificate with CA certificate.
     * 
     * @param certificate X.509 certificate to verify. May not be null.
     * @param caCertChain Collection of X509Certificates. May not be null, an empty list or a Collection with null entries.
     * @return true if verified OK
     * @throws CertPathValidatorException if verification failed
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static boolean verify(X509Certificate certificate, Collection<X509Certificate> caCertChain) throws CertPathValidatorException {
        return X509CertificateTools.verify(certificate, caCertChain);
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
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static boolean verifyWithTrustedCertificates(X509Certificate certificate, List< Collection<X509Certificate>> trustedCertificates, PKIXCertPathChecker...pkixCertPathCheckers) {
        return X509CertificateTools.verifyWithTrustedCertificates(certificate, trustedCertificates, pkixCertPathCheckers);
    }

    /**
     * Checks that the given date is within the certificate's validity period. In other words, this determines whether the certificate would be valid
     * at the given date/time.
     * 
     * This utility class is only a helper to get the same behavior as the standard java.security.cert API regardless if using X.509 or CV
     * Certificate.
     * 
     * @param cert certificate to verify, if null the method returns immediately, null does not have a validity to check.
     * @param date the Date to check against to see if this certificate is valid at that date/time.
     * @throws NoSuchFieldException
     * @throws CertificateExpiredException - if the certificate has expired with respect to the date supplied.
     * @throws CertificateNotYetValidException - if the certificate is not yet valid with respect to the date supplied.
     * @see java.security.cert.X509Certificate#checkValidity(Date)
     */
    public static void checkValidity(final Certificate cert, final Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        if (cert != null) {
            if (cert instanceof X509Certificate) {
                final X509Certificate xcert = (X509Certificate) cert;
                X509CertificateTools.checkValidity(xcert, date);
            } else if (StringUtils.equals(cert.getType(), "CVC")) {
                final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
                try {
                    final Date start = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
                    final Date end = cvccert.getCVCertificate().getCertificateBody().getValidTo();
                    if (start.after(date)) {
                        String msg = "CV Certificate startDate '" + start + "' is after check date '" + date + "'. Subject: "+CertTools.getSubjectDN(cert);
                        if (log.isTraceEnabled()) {
                            log.trace(msg);
                        }
                        throw new CertificateNotYetValidException(msg);
                    }
                    if (end.before(date)) {
                        final String msg = "CV Certificate endDate '" + end + "' is before check date '" + date + "'. Subject: "+CertTools.getSubjectDN(cert);
                        if (log.isTraceEnabled()) {
                            log.trace(msg);
                        }
                        throw new CertificateExpiredException(msg);
                    }
                } catch (NoSuchFieldException e) {
                    log.error("NoSuchFieldException: ", e);
                }
            }
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
    public static String getCrlDistributionPoint(final Certificate certificate) {
        if(certificate instanceof X509Certificate) {
            return CrlTools.getCrlDistributionPoint((X509Certificate) certificate);
        }
        return null;
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
        return CrlTools.getCrlDistributionPoints(x509cert);
    }

    /**
     * Extracts the URIs from a CRL Issuing Distribution Point extension of a CRL.
     * @param extensionValue Extension value of a CRL Issuing Distribution Point extension
     * @return List of URIs
     */
    public static List<String> getCrlDistributionPoints(final ASN1Primitive extensionValue) {
        return CrlTools.getCrlDistributionPoints(extensionValue);
    }

    /**
     * Return a list of CRL Issuing Distribution Points URIs from a CRL.
     * @see #getCrlDistributionPoints(X509Certificate)
     * @param crl CRL
     * @return A list of URIs
     */
    public static List<String> getCrlDistributionPoints(final X509CRL crl) {
        return CrlTools.getCrlDistributionPoints(crl);
    }

    /**
     * This utility method extracts the Authority Information Access Extention's URLs
     * 
     * @param crl a CRL to parse
     * @return the Authority Information Access Extention's URLs, or an empty Collection if none were found
     * 
     * @deprecated Use the equivalent method in CrlTools
     */
    @Deprecated
    public static Collection<String> getAuthorityInformationAccess(CRL crl) {    
        return CrlTools.getAuthorityInformationAccess(crl);
    }

    /**
     * @return all CA issuer URI that are inside AuthorityInformationAccess extension or an empty list
     */
    public static List<String> getAuthorityInformationAccessCAIssuerUris(Certificate cert) {
        List<String> urls = new ArrayList<>();
        if(cert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) cert;
            urls = X509CertificateTools.getAuthorityInformationAccessCAIssuerUris(x509cert);
        }
        return urls;
    }
    
    
    /**
     * Returns the first OCSP URL that is inside AuthorityInformationAccess extension, or null.
     * 
     * @param cert is the certificate to parse
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getAuthorityInformationAccessOcspUrl(X509Certificate cert) {
        return X509CertificateTools.getAuthorityInformationAccessOcspUrl(cert);
    }
    
    /**
     * @return all OCSP URL that is inside AuthorityInformationAccess extension or an empty list
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static List<String> getAuthorityInformationAccessOcspUrls(Certificate cert) {
        if (cert instanceof X509Certificate) {
            return X509CertificateTools.getAuthorityInformationAccessOcspUrls((X509Certificate) cert);
        } else {
            return new ArrayList<>();
        }
    }
    
    
    /** @return PrivateKeyUsagePeriod extension from a certificate */
    public static PrivateKeyUsagePeriod getPrivateKeyUsagePeriod(final X509Certificate cert) {
        PrivateKeyUsagePeriod res = null;
        final byte[] extvalue = cert.getExtensionValue(Extension.privateKeyUsagePeriod.getId());
        if (extvalue != null && extvalue.length > 0) {
            if (log.isTraceEnabled()) {
                log.trace("Found a PrivateKeyUsagePeriod in the certificate with subject: " + cert.getSubjectDN().toString());
            }
            res = PrivateKeyUsagePeriod.getInstance(DEROctetString.getInstance(extvalue).getOctets());
        }
        return res;
    }

    /**
     * 
     * @param cert An X509Certificate
     * @param oid An OID for an extension 
     * @return an Extension ASN1Primitive from a certificate, or null
     */
    protected static ASN1Primitive getExtensionValue(X509Certificate cert, String oid) {
        return X509CertificateTools.getExtensionValue(cert, oid);
    }

    /**
     * 
     * @param crl an X509CRL
     * @param oid An OID for an extension 
     * @return an Extension ASN1Primitive from a CRL
     */
    protected static ASN1Primitive getExtensionValue(X509CRL crl, String oid) {
        return CrlTools.getExtensionValue(crl, oid);
    }

    /** @return the PKCS#10's extension of the specified OID or null if no such extension exists */
    public static Extension getExtension(final PKCS10CertificationRequest pkcs10CertificateRequest, String oid) {
        if (pkcs10CertificateRequest != null && oid != null) {
            final Extensions extensions = getPKCS10Extensions(pkcs10CertificateRequest);
            if (extensions!=null) {
                return extensions.getExtension(new ASN1ObjectIdentifier(oid));
            }
        }
        return null;
    }

    /** @return the first found extensions or null if PKCSObjectIdentifiers.pkcs_9_at_extensionRequest was not present in the PKCS#10 */
    private static Extensions getPKCS10Extensions(final PKCS10CertificationRequest pkcs10CertificateRequest) {
        final Attribute[] attributes = pkcs10CertificateRequest.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (final Attribute attribute : attributes) {
            final ASN1Set attributeValues = attribute.getAttrValues();
            if (attributeValues.size()>0) {
                return Extensions.getInstance(attributeValues.getObjectAt(0));
            }
        }
        return null;
    }

    /**
     * Generate SHA1 fingerprint of certificate in string representation.
     * 
     * @param cert Certificate.
     * 
     * @return String containing hex format of SHA1 fingerprint (lower case), or null if input is null.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools} 
     */
    @Deprecated
    public static String getFingerprintAsString(Certificate cert) {
        return X509CertificateTools.getFingerprintAsString(cert);
    }

    /**
     * Generate SHA1 fingerprint of CRL in string representation.
     * 
     * @param crl X509CRL.
     * 
     * @return String containing hex format of SHA1 fingerprint.
     * 
     * @deprecated Use the equivalent method in {@link CrlTools} 
     */
    @Deprecated
    public static String getFingerprintAsString(X509CRL crl) {
        return CrlTools.getFingerprintAsString(crl);
    }

    /**
     * Generate SHA1 fingerprint of byte array in string representation.
     * 
     * @param in byte array to fingerprint.
     * 
     * @return String containing hex format of SHA1 fingerprint.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getFingerprintAsString(byte[] in) {
        return X509CertificateTools.getFingerprintAsString(in);
    }

    /**
     * Generate SHA256 fingerprint of byte array in string representation.
     * 
     * @param in byte array to fingerprint.
     * 
     * @return String containing hex format of SHA256 fingerprint.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getSHA256FingerprintAsString(byte[] in) {
        return X509CertificateTools.getSHA256FingerprintAsString(in);
    }

    /**
     * Generate a SHA1 fingerprint from a byte array containing a certificate
     * 
     * @param ba Byte array containing DER encoded Certificate or CRL.
     * 
     * @return Byte array containing SHA1 hash of DER encoded certificate.
     * 
     * @deprecated User the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static byte[] generateSHA1Fingerprint(byte[] ba) {
        return X509CertificateTools.generateSHA1Fingerprint(ba);
    } 

    /**
     * Generate a SHA256 fingerprint from a byte array containing a certificate
     * 
     * @param ba Byte array containing DER encoded Certificate or CRL.
     * 
     * @return Byte array containing SHA256 hash of DER encoded certificate.
     * 
     * @deprecated User the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static byte[] generateSHA256Fingerprint(byte[] ba) {
        return X509CertificateTools.generateSHA256Fingerprint(ba);
    } 
    
    /**
     * Generate a MD5 fingerprint from a byte array containing a certificate
     * 
     * @param ba Byte array containing DER encoded Certificate.
     * 
     * 
     * @deprecated User the equivalent method from {@link X509CertificateTools}
     */
    @Deprecated
    public static byte[] generateMD5Fingerprint(byte[] ba) {
        return X509CertificateTools.generateMD5Fingerprint(ba);
    }

    /**
     * Converts Sun Key usage bits to Bouncy castle key usage bits.
     * 
     * @param sku key usage bit fields according to java.security.cert.X509Certificate#getKeyUsage, must be a boolean array of size 9.
     * @return key usage int according to org.bouncycastle.jce.X509KeyUsage#X509KeyUsage, or -1 if input is null.
     * @see java.security.cert.X509Certificate#getKeyUsage
     * @see org.bouncycastle.jce.X509KeyUsage#X509KeyUsage
     */
    public static int sunKeyUsageToBC(boolean[] sku) {
        if (sku == null) {
            return -1;
        }
        int bcku = 0;
        if (sku[0]) {
            bcku = bcku | X509KeyUsage.digitalSignature;
        }
        if (sku[1]) {
            bcku = bcku | X509KeyUsage.nonRepudiation;
        }
        if (sku[2]) {
            bcku = bcku | X509KeyUsage.keyEncipherment;
        }
        if (sku[3]) {
            bcku = bcku | X509KeyUsage.dataEncipherment;
        }
        if (sku[4]) {
            bcku = bcku | X509KeyUsage.keyAgreement;
        }
        if (sku[5]) {
            bcku = bcku | X509KeyUsage.keyCertSign;
        }
        if (sku[6]) {
            bcku = bcku | X509KeyUsage.cRLSign;
        }
        if (sku[7]) {
            bcku = bcku | X509KeyUsage.encipherOnly;
        }
        if (sku[8]) {
            bcku = bcku | X509KeyUsage.decipherOnly;
        }
        return bcku;
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
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String insertCNPostfix(String dn, String cnpostfix, X500NameStyle nameStyle) {
        return X509CertificateTools.insertCNPostfix(dn, cnpostfix, nameStyle);
    }

    /**
     * Splits a DN into components.
     * @see X509NameTokenizer
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static List<String> getX500NameComponents(String dn) {
        return X509CertificateTools.getX500NameComponents(dn);
    }

    /**
     * Returns the parent DN of a DN string, e.g. if the input is
     * "cn=User,dc=example,dc=com" then it would return "dc=example,dc=com".
     * Returns an empty string if there is no parent DN.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static String getParentDN(String dn) {
        return X509CertificateTools.getParentDN(dn);
    }

 
    /**
     * EJBCA accepts extension OIDs on different formats, e.g. "1.2.3.4" and "1.2.3.4.value".
     * Method returns the OID only given any OID string
     * @param oidString to parse
     * @return String containing OID only or null if no OID was found in the input string
     */
    public static String getOidFromString(final String oidString) {
        String retval = oidString;
        // Matches anything but numerical and dots
        final Pattern pattern = Pattern.compile("[^0-9.]");
        final Matcher matcher = pattern.matcher(oidString);
        if (matcher.find()) {
            int endIndex = matcher.start();
            if (endIndex == 0) {
                return null;
            }
            retval = oidString.substring(0, endIndex-1);
        }
        return retval;
    }
    
    /**
     * Returns the regex match pattern given an OID wildcard.
     * @param oidWildcard wildcard. E.g. 1.2.*.3
     * @return regex match pattern
     */
    public static String getOidWildcardPattern(final String oidWildcard) {
        // First escape all '.' which are interpreted as regex wildcards themselves.
        // Secondly, generate the pattern where '*' is the wildcard character
        final String wildcardMatchPattern = oidWildcard.replaceAll("\\.", "\\\\.").replaceAll("\\*", "([0-9.]*)");
        return wildcardMatchPattern;
    }

    /**
     * Method to create certificate path and to check it's validity from a list of certificates. The list of certificates should only contain one root
     * certificate. The created certificate chain is checked to be valid at the current date and time.
     * 
     * @param certlistin List of certificates to create certificate chain from.
     * @return the certificatepath with the root CA at the end
     * @throws CertPathValidatorException if the certificate chain can not be constructed or validated
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static List<Certificate> createCertChain(Collection<?> certlistin) throws CertPathValidatorException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
        return createCertChain(certlistin, new Date());
    }

    /**
     * Method to create certificate path and to check it's validity from a list of certificates. The list of certificates should only contain one root
     * certificate.
     * 
     * @param certlistin List of certificates (X.509, CVC, or other supported) to create certificate chain from.
     * @param now Date to use when checking if the CAs chain is valid.
     * @return the certificate path with the root CA at the end
     * @throws CertPathValidatorException if the certificate chain can not be constructed
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static List<Certificate> createCertChain(Collection<?> certlistin, Date now) throws CertPathValidatorException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
        final List<Certificate> returnval = new ArrayList<>();

        Collection<Certificate> certlist = orderCertificateChain(certlistin);
        // Verify that the chain contains a Root CA certificate
        Certificate rootca = null;
        for(Certificate crt : certlist) {
            if (CertTools.isSelfSigned(crt)) {
                rootca = crt;
            }
        }
        if (rootca == null) {
            throw new CertPathValidatorException("No root CA certificate found in certificate list");
        }

        // set certificate chain
        Certificate rootcert = null;
        ArrayList<Certificate> calist = new ArrayList<>();
        for (Certificate next : certlist) {
            if (CertTools.isSelfSigned(next)) {
                rootcert = next;
            } else {
                calist.add(next);
            }
        }

        if (calist.isEmpty()) {
            // only one root cert, no certchain
            returnval.add(rootcert);
        } else {
            // We need a bit special handling for CV certificates because those can not be handled using a PKIX CertPathValidator
            Certificate test = calist.get(0);
            if (test.getType().equals("CVC")) {
                if (calist.size() == 1) {
                    returnval.add(test);
                    returnval.add(rootcert);
                } else {
                    throw new CertPathValidatorException("CVC certificate chain can not be of length longer than two.");
                }
            } else {
                // Normal X509 certificates
                HashSet<TrustAnchor> trustancors = new HashSet<>();
                TrustAnchor trustanchor = null;
                trustanchor = new TrustAnchor((X509Certificate) rootcert, null);
                trustancors.add(trustanchor);

                // Create the parameters for the validator
                PKIXParameters params = new PKIXParameters(trustancors);

                // Disable CRL checking since we are not supplying any CRLs
                params.setRevocationEnabled(false);
                params.setDate(now);

                // Create the validator and validate the path
                CertPathValidator certPathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType(), BouncyCastleProvider.PROVIDER_NAME);
                CertificateFactory fact = CertTools.getCertificateFactory();
                CertPath certpath = fact.generateCertPath(calist);

                CertPathValidatorResult result = certPathValidator.validate(certpath, params);

                // Get the certificates validate in the path
                PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult) result;
                returnval.addAll(certpath.getCertificates());

                // Get the CA used to validate this path
                TrustAnchor ta = pkixResult.getTrustAnchor();
                X509Certificate cert = ta.getTrustedCert();
                returnval.add(cert);
            }
        }
        return returnval;
    } // createCertChain

    /**
     * Method ordering a list of certificate (X.509, CVC, or other supported type) into a certificate path with the root CA at the end. Does not check validity or verification of any kind,
     * just ordering by issuerdn.
     * 
     * @param certlist list of certificates to order can be collection of Certificate or byte[] (der encoded certs), must contain a full chain.
     * @return List with certificatechain, Root CA last.
     */
    private static List<Certificate> orderCertificateChain(Collection<?> certlist) throws CertPathValidatorException {
        ArrayList<Certificate> returnval = new ArrayList<>();
        Certificate rootca = null;
        HashMap<String, Certificate> cacertmap = new HashMap<>();
        for(Object possibleCertificate : certlist) {
            Certificate cert = null;
            try {
                cert = (Certificate) possibleCertificate;
            } catch (ClassCastException e) {
                // This was not a certificate, is it byte encoded?
                byte[] certBytes = (byte[]) possibleCertificate;
                try {
                    cert = CertTools.getCertfromByteArray(certBytes);
                } catch (CertificateParsingException e1) {
                    throw new CertPathValidatorException(e1);
                }
            }
            if (CertTools.isSelfSigned(cert)) {
                rootca = cert;
            } else {
                log.debug("Adding to cacertmap with index '" + CertTools.getIssuerDN(cert) + "'");
                cacertmap.put(CertTools.getIssuerDN(cert), cert);
            }
        }

        if (rootca == null) {
            throw new CertPathValidatorException("No root CA certificate found in certificatelist");
        }
        returnval.add(0, rootca);
        Certificate currentcert = rootca;
        int i = 0;
        while (certlist.size() != returnval.size() && i <= certlist.size()) {
            if (log.isDebugEnabled()) {
                log.debug("Looking in cacertmap for '" + CertTools.getSubjectDN(currentcert) + "'");
            }
            Certificate nextcert = cacertmap.get(CertTools.getSubjectDN(currentcert));
            if (nextcert == null) {
                if(log.isDebugEnabled()) {
                    log.debug("Dumping keys of CA certificate map:");
                    for(String issuerDn : cacertmap.keySet()) {
                        log.debug(issuerDn);
                    }
                }
                throw new CertPathValidatorException("Error building certificate path. Could find certificate with SubjectDN " 
                        + CertTools.getSubjectDN(currentcert) + " in certificate map. See debug log for details.");
            }
            returnval.add(0, nextcert);
            currentcert = nextcert;
            i++;
        }

        if (i > certlist.size()) {
            throw new CertPathValidatorException("Error building certificate path");
        }

        return returnval;
    } // orderCertificateChain

    public static boolean isCertListValidAndIssuedByCA(List<X509Certificate> certs, CAInfo cainfo) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertPathBuilderException, CertPathValidatorException {
        if (certs == null || certs.isEmpty()) {
            throw new IllegalArgumentException("extraCerts must contain at least one certificate.");
        }
        // What we got in extraCerts can be different things
        // - An end entity certificate only, signed by a SubCA or a RootCA
        // -- We need to find both SubCA and RootCA here, should be in cainfo?
        // - An end entity certificate and a SubCA certificate
        // -- We need to find the RootCA certificate only, should be in cainfo?
        // - An end entity certificate a SubCA certificate and a RootCA certificate
        // -- We need to remove the CA certificates that are not part of cainfo
        ArrayList<Certificate> certlist = new ArrayList<>();
        // Create CertPath
        certlist.addAll(certs);
        // Move CA certificates into cert path, except root certificate which is the trust anchor
        X509Certificate rootcert = null;
        Collection<Certificate> trustedCertificates = cainfo.getCertificateChain();
        final Iterator<Certificate> itr = trustedCertificates.iterator();
        while (itr.hasNext()) {
            // Trust anchor is last, so if this is the last element, don't add it
            Certificate crt = itr.next();
            if (itr.hasNext()) {
                if (!certlist.contains(crt)) {
                    certlist.add(crt);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Certlist already contains certificate with subject "+CertTools.getSubjectDN(crt)+", not adding to list");
                    }
                }
            } else {
                rootcert = (X509Certificate)crt;
                if (log.isDebugEnabled()) {
                    log.debug("Using certificate with subject "+CertTools.getSubjectDN(crt)+", as trust anchor, removing from certlist if it is there");
                }
                // Don't have the trust anchor in the cert path, remove doesn't do anything if rootcert doesn't exist in certlist
                certlist.remove(rootcert);
            }
        }
        // Get a CertPath that can order certificate chains well...
        CollectionCertStoreParameters storeParams = new CollectionCertStoreParameters(certlist);
        CertStore store = CertStore.getInstance("Collection", storeParams, BouncyCastleProvider.PROVIDER_NAME);
        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
        X509CertSelector pathConstraints = new X509CertSelector();
        //pathConstraints.setCertificate(endCert);
        TrustAnchor anchor = new TrustAnchor(rootcert, null);
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(anchor), pathConstraints);
        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);
        PKIXCertPathBuilderResult pathresult = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath cp = pathresult.getCertPath();

        // The end entity cert is the first one in the CertPath according to javadoc
        // - "By convention, X.509 CertPaths (consisting of X509Certificates), are ordered starting with the target
        //    certificate and ending with a certificate issued by the trust anchor.
        //    That is, the issuer of one certificate is the subject of the following one."
        // Note: CertPath above will most likely not sort the path, at least if there is a root cert in certlist
        // the cp will fail verification if it was not in the right order in certlist to start with
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);
        params.setSigProvider(BouncyCastleProvider.PROVIDER_NAME);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
        if (log.isDebugEnabled()) {
            log.debug("Certificate verify result: " + result.toString());
        }
        // No CertPathValidatorException thrown means it passed
        return true;
    }
    
    /**
     * @return true if the chains are nonempty, contain the same certificates in the same order
     */
    public static boolean compareCertificateChains(Certificate[] chainA, Certificate[] chainB) {
        if (chainA == null || chainB == null) {
            return false;
        }
        if (chainA.length != chainB.length) {
            return false;
        }
        for (int i = 0; i < chainA.length; i++) {
            if (chainA[i] == null || !chainA[i].equals(chainB[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Dumps a certificate (cvc or x.509) to string format, suitable for manual inspection/debugging.
     * 
     * @param cert Certificate
     * 
     * @return String with cvc or asn.1 dump.
     */
    public static String dumpCertificateAsString(final Certificate cert) {
        String ret = null;
        if (cert instanceof X509Certificate) {
            try {
                final X509Certificate c = X509CertificateTools.parseCertificate(BouncyCastleProvider.PROVIDER_NAME, cert.getEncoded());
                ret = c.toString();
            } catch (CertificateException e) {
                ret = e.getMessage();
            }
        } else if (StringUtils.equals(cert.getType(), "CVC")) {
            final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
            final CVCObject obj = cvccert.getCVCertificate();
            ret = obj.getAsText("");
        } else {
            throw new IllegalArgumentException("dumpCertificateAsString: Certificate of type " + cert.getType() + " is not implemented");
        }
        return ret;
    }
    
    /**
     * Creates PKCS10CertificateRequest object from PEM encoded certificate request
     * @param pemEncodedCsr PEM encoded CSR
     * @return PKCS10CertificateRequest object
     */
    public static PKCS10CertificationRequest getCertificateRequestFromPem(final String pemEncodedCsr){
        if(pemEncodedCsr == null){
            return null;
        }
        PKCS10CertificationRequest csr = null;
        final ByteArrayInputStream pemStream = new ByteArrayInputStream(pemEncodedCsr.getBytes(StandardCharsets.UTF_8));
        try (PEMParser pemParser = new PEMParser(new BufferedReader(new InputStreamReader(pemStream)));) {
            final Object parsedObj = pemParser.readObject();
            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;
            }
        } catch (IOException | DecoderException e) {//IOException that will be wrapped as (runtime) DecoderException
            log.info("IOException while decoding certificate request from PEM: " + e.getMessage());
            log.debug("IOException while decoding certificate request from PEM.", e);
        }
        return csr;
    }

    /**
     * Generates a PKCS10CertificationRequest
     * 
     * Code Example:
     * -------------
     * An example of putting AltName and a password challenge in an 'attributes' set (taken from RequestMessageTest.test01Pkcs10RequestMessage() ):
     *       
     *      {@code
     *      // Create a P10 with extensions, in this case altNames with a DNS name
     *      ASN1EncodableVector altnameattr = new ASN1EncodableVector();
     *      altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
     *      // AltNames
     *      GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo1.bar.com");
     *      ExtensionsGenerator extgen = new ExtensionsGenerator();
     *      extgen.addExtension(Extension.subjectAlternativeName, false, san );
     *      Extensions exts = extgen.generate();
     *      altnameattr.add(new DERSet(exts));
     *    
     *      // Add a challenge password as well
     *      ASN1EncodableVector pwdattr = new ASN1EncodableVector();
     *      pwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
     *      ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
     *      pwdvalues.add(new DERUTF8String("foo123"));
     *      pwdattr.add(new DERSet(pwdvalues));
     *    
     *      // Complete the Attribute section of the request, the set (Attributes)
     *      // contains one sequence (Attribute)
     *      ASN1EncodableVector v = new ASN1EncodableVector();
     *      v.add(new DERSequence(altnameattr));
     *      v.add(new DERSequence(pwdattr));
     *      DERSet attributes = new DERSet(v);
     *      }
     * 
     * @param signatureAlgorithm the signature algorithm to sign the CSR.
     * @param subject the request's subject DN.
     * @param publickey the public key of the CSR.
     * @param attributes a set of attributes, for example, extensions, challenge password, etc.
     * @param privateKey the private key used to sign the CSR.
     * @param provider the JCA/JCE provider to use.
     * @return a PKCS10CertificateRequest based on the input parameters.
     * 
     * @throws OperatorCreationException if an error occurred while creating the signing key
     */
    // Should sign with. other private as well!
    public static PKCS10CertificationRequest genPKCS10CertificationRequest(String signatureAlgorithm, X500Name subject, PublicKey publickey,
            ASN1Set attributes, PrivateKey privateKey, String provider) throws OperatorCreationException {

        ContentSigner signer;
        CertificationRequestInfo reqInfo;
        try {
            SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publickey.getEncoded());
            reqInfo = new CertificationRequestInfo(subject, pkinfo, attributes);

            if (provider == null) {
                provider = BouncyCastleProvider.PROVIDER_NAME;
            }
            signer = new BufferingContentSigner(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(privateKey), 20480);
            signer.getOutputStream().write(reqInfo.getEncoded(ASN1Encoding.DER));
            signer.getOutputStream().flush();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }
        byte[] sig = signer.getSignature();
        DERBitString sigBits = new DERBitString(sig);

        CertificationRequest req = new CertificationRequest(reqInfo, signer.getAlgorithmIdentifier(), sigBits);
        return new PKCS10CertificationRequest(req);
    }

    /**
     * Create a "certs-only" PKCS#7 / CMS from the provided chain.
     * 
     * @param x509CertificateChain chain of certificates with the leaf in the first position and root in the last or just a leaf certificate.
     * @return a byte array containing the CMS
     * @throws CertificateEncodingException if the provided list of certificates could not be parsed correctly
     * @throws CMSException if there was a problem creating the certs-only CMS message
     *
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static byte[] createCertsOnlyCMS(final List<X509Certificate> x509CertificateChain) throws CertificateEncodingException, CMSException {
        return X509CertificateTools.createCertsOnlyCMS(x509CertificateChain);
    }

    /**
     * Generated Generates a ContentVerifierProvider.
     * 
     * @param pubkey
     * @return a JcaContentVerifierProvider. Useful for verifying the signiture in a PKCS10CertificationRequest
     * @throws OperatorCreationException
     */
    public static ContentVerifierProvider genContentVerifierProvider(PublicKey pubkey) throws OperatorCreationException {
        return new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pubkey);
    }

    /**
     * @return a Certificate Collection as a X509Certificate list
     * @throws ClassCastException if one of the Certificates in the collection is not an X509Certificate
     */
    public static final List<X509Certificate> convertCertificateChainToX509Chain(final Collection<Certificate> chain) throws ClassCastException {
        final List<X509Certificate> ret = new ArrayList<>();
        for (final Certificate certificate : chain) {
            ret.add((X509Certificate) certificate);
        }
        return ret;
    }
    
    
    /**
     * Converts a X509Certificate chain into a JcaX509CertificateHolder chain.
     * 
     * @param certificateChain input chain to be converted
     * @return the result
     * @throws CertificateEncodingException if there is a problem extracting the certificate information.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static final JcaX509CertificateHolder[] convertToX509CertificateHolder(X509Certificate[] certificateChain)
            throws CertificateEncodingException {
        return X509CertificateTools.convertToX509CertificateHolder(certificateChain);
    }
    
    /**
     * Converts a X509Certificate chain into a JcaX509CertificateHolder chain.
     * 
     * @param certificateChain input chain to be converted
     * @return the result
     * @throws CertificateEncodingException if there is a problem extracting the certificate information.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static final List<JcaX509CertificateHolder> convertToX509CertificateHolder(List<X509Certificate> certificateChain)
            throws CertificateEncodingException {
        return X509CertificateTools.convertToX509CertificateHolder(certificateChain);
    }

    /**
     * Converts a X509CertificateHolder chain into a X509Certificate chain.
     * 
     * @param certificateHolderChain input chain to be converted
     * @return the result
     * @throws CertificateException if there is a problem extracting the certificate information.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static final List<X509Certificate> convertToX509CertificateList(Collection<X509CertificateHolder> certificateHolderChain) throws CertificateException {
        return X509CertificateTools.convertToX509CertificateList(certificateHolderChain);
    }

    /**
     * Converts a X509CertificateHolder chain into a X509Certificate chain.
     * 
     * @param certificateHolderChain input chain to be converted
     * @return the result
     * @throws CertificateException if there is a problem extracting the certificate information.
     * 
     * @deprecated Use the equivalent method in {@link X509CertificateTools}
     */
    @Deprecated
    public static final X509Certificate[] convertToX509CertificateArray(Collection<X509CertificateHolder> certificateHolderChain) throws CertificateException {
        return convertToX509CertificateList(certificateHolderChain).toArray(new X509Certificate[0]);
    }

    /**
     * Converts a X509CertificateHolder chain into a X509Certificate chain.
     * 
     * @param crlHolders input chain to be converted
     * @return the result
     * @throws CRLException if there is a problem extracting the CRL information.
     * 
     * @deprecated Use the equivalent method in {@link CrlTools}
     */
    @Deprecated
    public static final List<X509CRL> convertToX509CRLList(Collection<X509CRLHolder> crlHolders) throws CRLException {
        final List<X509CRL> ret = new ArrayList<>();
        final JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();
        for (final X509CRLHolder crlHolder : crlHolders) {
            ret.add(jcaX509CRLConverter.getCRL(crlHolder));
        }
        return ret;
    }

    /**
     * Checks that the given SubjectDN / SAN satisfies the Name Constraints of the given issuer (if there are any).
     * This method checks the Name Constraints in the given issuer only. A complete implementation of
     * name constraints should check the whole certificate chain.
     * 
     * @param issuer Issuing CA.
     * @param subjectDNName Subject DN to check. Optional.
     * @param subjectAltName Subject Alternative Name to check. Optional.
     * @throws IllegalNameException if the name(s) didn't pass naming constraints 
     */
    public static void checkNameConstraints(X509Certificate issuer, X500Name subjectDNName, GeneralNames subjectAltName) throws IllegalNameException {
        final byte[] ncbytes = issuer.getExtensionValue(Extension.nameConstraints.getId());
        final ASN1OctetString ncstr = (ncbytes != null ? ASN1OctetString.getInstance(ncbytes) : null);
        final ASN1Sequence ncseq = (ncbytes != null ? ASN1Sequence.getInstance(ncstr.getOctets()) : null);
        final NameConstraints nc = (ncseq != null ? NameConstraints.getInstance(ncseq) : null);
        
        if (nc != null) {
            if (subjectDNName != null) {
                // Skip check for root CAs
                final X500Name issuerDNName = X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
                if (issuerDNName.equals(subjectDNName)) {
                    if (log.isTraceEnabled()) {
                        log.trace("Skipping test for Root CA: " + subjectDNName);
                    }
                    return;
                }
            }
          
            
            final PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
            
            GeneralSubtree[] permitted = nc.getPermittedSubtrees();
            GeneralSubtree[] excluded = nc.getExcludedSubtrees();
                        
            if (permitted != null) {
                
                GeneralSubtree[] permittedFormatted = new GeneralSubtree[permitted.length];
                
                for (int i = 0; i < permitted.length; i++) {
                    GeneralSubtree subtree = permitted[i];
                    log.trace("Permitted subtree: " + subtree.getBase());
                    log.trace(ASN1Dump.dumpAsString(subtree.getBase()));
                    
                    if(subtree.getBase().getTagNo() != GeneralName.uniformResourceIdentifier) {
                        permittedFormatted[i] = subtree;
                    } else {
                        String uri = subtree.getBase().getName().toString();
                        String host = extractHostFromURL(uri);
                        permittedFormatted[i] = new GeneralSubtree(
                                    new GeneralName(GeneralName.uniformResourceIdentifier, host));
                    }
                }
            
                validator.intersectPermittedSubtree(permittedFormatted);
            }
        
            if (excluded != null) {
                for (GeneralSubtree subtree : excluded) {
                    if (log.isTraceEnabled()) {
                        log.trace("Excluded subtree: " + subtree.getBase());
                        log.trace(ASN1Dump.dumpAsString(subtree.getBase()));
                    }
                    if(subtree.getBase().getTagNo() != GeneralName.uniformResourceIdentifier) {
                        validator.addExcludedSubtree(subtree);
                    } else {
                        String uri = subtree.getBase().getName().toString();
                        String host = extractHostFromURL(uri);
                        validator.addExcludedSubtree(new GeneralSubtree(
                                    new GeneralName(GeneralName.uniformResourceIdentifier, host)));
                    }
                }
            }

            if (subjectDNName != null) {
                GeneralName dngn = new GeneralName(subjectDNName);
                try {
                    validator.checkPermitted(dngn);
                    validator.checkExcluded(dngn);
                } catch (PKIXNameConstraintValidatorException e) {
                    final String dnStr = subjectDNName.toString();
                    final boolean isLdapOrder = dnHasMultipleComponents(dnStr) && !isDNReversed(dnStr);
                    if (isLdapOrder) {
                        final String msg = "Must use X.500 DN order (not LDAP DN order) when issuing a certificate with Name Constraints.";
                        throw new IllegalNameException(msg);
                    } else {
                        final String msg = "Subject DN '" + subjectDNName + "' does not fulfill Name Constraints of issuing CA.";
                        throw new IllegalNameException(msg, e);
                    }
                }
            }
            
            if (subjectAltName != null) {
                for (GeneralName sangn : subjectAltName.getNames()) {
                    try {
                        validator.checkPermitted(sangn);
                        if (sangn.getTagNo() == 2 && isAllDNSNamesExcluded(excluded)) {
                            final String msg = "Subject Alternative Name '" + NameConstraint.getNameConstraintFromType(sangn.getTagNo()) + ":"
                                    + sangn.toString().substring(2) + "' does not fulfill name constraints of issuing CA.";
                                    ;
                            throw new IllegalNameException(msg);
                        }
                        validator.checkExcluded(sangn);
                    } catch (PKIXNameConstraintValidatorException e) {
                        final String msg = "Subject Alternative Name '" + NameConstraint.getNameConstraintFromType(sangn.getTagNo()) + ":"
                                + sangn.toString().substring(2) + "' does not fulfill name constraints of issuing CA.";
                        throw new IllegalNameException(msg, e);
                    }
                }
            }
        }
    }
    
    /**
     * Checks if a DN has at least two components. Then the DN can be in either LDAP or X500 order.
     * Otherwise it's not possible to determine the order.
     */
    private static boolean dnHasMultipleComponents(String dn) {
        final X509NameTokenizer xt = new X509NameTokenizer(dn);
        if (xt.hasMoreTokens()) {
            xt.nextToken();
            return xt.hasMoreTokens();
        }
        return false;
    }
    
    // Check if we should exclude all dns names
    private static boolean isAllDNSNamesExcluded(GeneralSubtree[] excluded) {
        if (Objects.isNull(excluded)) {
            return false;
        }
        
        for (int i = 0; i < excluded.length; i++) {
            if (excluded[i].getBase().toString().equals("2: ")) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Refers private method from org.bouncycastle.asn1.x509.PKIXNameConstraintValidator.
     * It is used here to extract host from name constraint in CA. Bouncy Castle extracts host
     * from the URIs in subjectDN or subjectAlternativeName.
     * 
     * @param url
     * @return
     */
    private static String extractHostFromURL(String url) {
        // see RFC 1738
        // remove ':' after protocol, e.g. https:
        String sub = url.substring(url.indexOf(':') + 1);
        // extract host from Common Internet Scheme Syntax, e.g. https://
        if (sub.indexOf("//") != -1) {
            sub = sub.substring(sub.indexOf("//") + 2);
        }
        // first remove port, e.g. https://test.com:21
        if (sub.lastIndexOf(':') != -1) {
            sub = sub.substring(0, sub.lastIndexOf(':'));
        }
        // remove user and password, e.g. https://john:password@test.com
        sub = sub.substring(sub.indexOf(':') + 1);
        sub = sub.substring(sub.indexOf('@') + 1);
        // remove local parts, e.g. https://test.com/bla
        if (sub.indexOf('/') != -1) {
            sub = sub.substring(0, sub.indexOf('/'));
        }
        return sub;
    }

   
    
    /**
     * Creates a public key fingerprint with the given digest algorithm and returns it hex encoded. 
     * 
     * @param publicKey the public key.
     * @param algorithm the digest algorithm (i.e. MD-5, SHA-1, SHA-256, etc.)
     * @return the public key fingerprint, hex encoded, or null.
     */
    public static final String createPublicKeyFingerprint(final PublicKey publicKey, final String algorithm) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.reset();
            digest.update(publicKey.getEncoded());
            final String result = Hex.toHexString(digest.digest());
            if (log.isDebugEnabled()) {
                log.debug("Fingerprint " + result + " created for public key: " + new String(Base64.encode(publicKey.getEncoded())));
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            log.warn("Could not create fingerprint for public key ", e);
            return null;
        }
    }

    /**
     * Get first commonName value from subjectDn. If none is present, return null
     * @param subjectDn subjectDn value
     * @return First commonName, or null
     */
    public static String getCommonNameFromSubjectDn(String subjectDn) {
        String commonName = null;
        if(subjectDn != null) {
            List<String> commonNames = X509CertificateTools.getPartsFromDN(subjectDn, "CN");
            if (!commonNames.isEmpty() && StringUtils.isNotEmpty(commonNames.get(0))) {
                commonName = commonNames.get(0);
            }
        }
        return commonName;
    }

    public static byte[] getPKCS7Certificate(InputStream is) throws CertificateException, IOException, CMSException {
        final InputStreamReader isr = new InputStreamReader(is);
        try (final PEMParser parser = new PEMParser(isr)) {
            final ContentInfo info = (ContentInfo) parser.readObject();
            final CMSSignedData csd = new CMSSignedData(info);
            return csd.getEncoded();
        }
    }

    @Deprecated
    public static String getPEMCertificate(Collection<X509CertificateHolder> collection) throws CertificateException {     
        return X509CertificateTools.getPEMCertificate(collection);
    }

    @Deprecated
    public static String getPEMCertificate(byte[] bytes) {
        return X509CertificateTools.getPEMCertificate(bytes);
    }

    public static String getPKCS7PEMCertificate(byte[] bytes) {
        final byte[] b64 = Base64.encode(bytes);
        return BEGIN_PKCS7 + "\n" + new String(b64) + "\n" + END_PKCS7;
    }

    public static byte[] getFirstCertificateFromPKCS7(byte[] pkcs7) throws CMSException, IOException {
        byte[] firstCertificate = null;

        final CMSSignedData csd = new CMSSignedData(pkcs7);
        final Store<X509CertificateHolder> certstore = csd.getCertificates();
        final Collection<X509CertificateHolder> collection = certstore.getMatches(null);

        final Iterator<X509CertificateHolder> ci = collection.iterator();
        if (ci.hasNext()) {
            firstCertificate = ci.next().getEncoded();
        }

        return firstCertificate;
    }

    /**
     * Simple methods that returns the signature algorithm value from the certificate. Not usable for setting signature algorithms names in EJBCA,
     * only for human presentation.
     *
     * @return Signature algorithm name from the certificate as a human readable string, for example SHA1WithRSA.
     */
    public static String getCertSignatureAlgorithmNameAsString(Certificate cert) {
        final String certSignatureAlgorithm;
        {
            final String certSignatureAlgorithmTmp;
            if (cert instanceof X509Certificate) {
                final X509Certificate x509cert = (X509Certificate) cert;
                certSignatureAlgorithmTmp = x509cert.getSigAlgName();
                if (AlgorithmTools.log.isDebugEnabled()) {
                    AlgorithmTools.log.debug("certSignatureAlgorithm is: " + certSignatureAlgorithmTmp);
                }
            } else if (StringUtils.equals(cert.getType(), "CVC")) {
                final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
                final CVCPublicKey cvcpk;
                try {
                    cvcpk = cvccert.getCVCertificate().getCertificateBody().getPublicKey();
                    final OIDField oid = cvcpk.getObjectIdentifier();
                    certSignatureAlgorithmTmp = AlgorithmUtil.getAlgorithmName(oid);
                } catch (NoSuchFieldException e) {
                    throw new IllegalStateException("Not a valid CVC certificate", e);
                }
            } else {
                throw new IllegalStateException("Certificate type neither X509 nor CVS.");
            }
            // Try to make it easier to display some signature algorithms that cert.getSigAlgName() does not have a good string for.
            // We typically don't get here, since the x509cert.getSigAlgName handles id_RSASSA_PSS nowadays, this is old legacy code,
            // only triggered if the resulting signature algorithm returned above is an OID in stead of a sign alg name
            // (i.e. 1.2.840.113549.1.1.10 instead of SHA256WithRSAAndMGF1
            if (certSignatureAlgorithmTmp.equalsIgnoreCase(PKCSObjectIdentifiers.id_RSASSA_PSS.getId()) && cert instanceof X509Certificate) {
                // Figure out the hash algorithm, it's hidden in the Signature Algorithm Parameters when using RSA PSS
                // If we got this value we should have a x509 cert
                final X509Certificate x509cert = (X509Certificate) cert;
                final byte[] params = x509cert.getSigAlgParams();
                // Below code snipped from BC, it's hidden as private/protected methods so we can't use BC directly.
                final RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);
                String digestName = MessageDigestUtils.getDigestName(rsaParams.getHashAlgorithm().getAlgorithm());
                // This is just to convert SHA-256 into SHA256, while SHA3-256 should remain as it is
                if (digestName.contains("-") && !digestName.startsWith("SHA3")) {
                    digestName = StringUtils.remove(digestName, '-');
                }
                certSignatureAlgorithm = digestName + "withRSAandMGF1";
            } else {
                certSignatureAlgorithm = certSignatureAlgorithmTmp;
            }
        }
        // EdDSA does not work to be translated (JDK11)
        if (certSignatureAlgorithm.equalsIgnoreCase(EdECObjectIdentifiers.id_Ed25519.getId())) {
            return AlgorithmConstants.SIGALG_ED25519;
        }
        if (certSignatureAlgorithm.equalsIgnoreCase(EdECObjectIdentifiers.id_Ed448.getId())) {
            return AlgorithmConstants.SIGALG_ED448;
        }
        // SHA256WithECDSA does not work to be translated in JDK5.
        if (certSignatureAlgorithm.equalsIgnoreCase(X9ObjectIdentifiers.ecdsa_with_SHA256.getId())) {
            return AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
        }
        // GOST3410
        if(AlgorithmTools.isGost3410Enabled() && certSignatureAlgorithm.equalsIgnoreCase(CesecoreConfiguration.getOidGost3410())) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410;
        }
        // DSTU4145
        if(AlgorithmTools.isDstu4145Enabled() && certSignatureAlgorithm.startsWith(CesecoreConfiguration.getOidDstu4145()+".")) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145;
        }
        return certSignatureAlgorithm;
    }
    
}
