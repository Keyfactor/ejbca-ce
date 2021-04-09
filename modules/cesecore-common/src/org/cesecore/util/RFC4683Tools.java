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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.util.DnComponents;

/**
 * Helper class to handle operations for RFC4683 certificate extension Subject Identification method (SIM) for 
 * including a privacy-sensitive identifier in the subjectAltName extension of a certificate. The SIM is 
 * an optional feature that may be used by relying parties to determine whether the subject of a particular 
 * certificate is also the person corresponding to a particular sensitive identifier 
 * (see <a href="https://tools.ietf.org/html/rfc4683">RFC 4683</a>).
 */
public final class RFC4683Tools {

    /** List separator to separate the SIM tokens in the internal storage format (also has to be entered by the user). */
    public static final String LIST_SEPARATOR = "::";

    /** Label for SIM rendered in the certificate. */
    public static final String SUBJECTIDENTIFICATIONMETHOD = "subjectIdentificationMethod";

    /** OID for SIM written into the certificate. */
    public static final String SUBJECTIDENTIFICATIONMETHOD_OBJECTID = "1.3.6.1.5.5.7.8.6";

    private static final Logger LOG = Logger.getLogger(RFC4683Tools.class);

    /**
     * Gets the allowed hash algorithm object identifiers (see <a href="https://tools.ietf.org/html/rfc4683#section-4.3">RFC 4683 section 4.3</a>).
     * @return a list of ASN1ObjectIdentifier {@link TSPAlgorithms#ALLOWED}.
     */
    @SuppressWarnings("unchecked")
    public static final List<ASN1ObjectIdentifier> getAllowedHashAlgorithms() {
        return new ArrayList<ASN1ObjectIdentifier>(TSPAlgorithms.ALLOWED);
    }

    /**
     * Gets the allowed hash algorithm OID strings.
     * @return a list of OID strings {@link TSPAlgorithms#ALLOWED}.
     */
    public static final List<String> getAllowedHashAlgorithmOidStrings() {
        final List<ASN1ObjectIdentifier> identifiers = getAllowedHashAlgorithms();
        final List<String> result = new ArrayList<>(identifiers.size());
        for (ASN1ObjectIdentifier identifier : identifiers) {
            result.add(identifier.getId());
        }
        return result;
    }

    /** This method reads the internal storage format for SAN. 
     * If the SAN contains SIM parameters (list of 4 tokens, separated by '::'), the parameters are replaced by 
     * the generated SIM strings (list of 3 tokens, separated by '::') {@link RFC4683Tools#generateInternalSimString(String, String, String, String)}
     * 
     * @param san the SAN string in internal storage format with SIM as user parameters.
     * @return SAN string in internal storage format with generated SIM strings, or just the original string if there was no SIM.
     */
    public static final String generateSimForInternalSanFormat(String san)
            throws IllegalArgumentException, NoSuchProviderException, NoSuchAlgorithmException {
        if (StringUtils.isNotBlank(san) && san.toUpperCase().contains(DnComponents.SUBJECTIDENTIFICATIONMETHOD)) {
            final List<String> sims = CertTools.getPartsFromDN(san, DnComponents.SUBJECTIDENTIFICATIONMETHOD);
            for (String sim : sims) {
                if (LOG.isDebugEnabled()) {
                    LOG.info("Store user SIM strings: " + sims);
                }
                if (StringUtils.isNotBlank(sim)) {
                    final String[] tokens = sim.split(LIST_SEPARATOR);
                    // was entered as hash, password, SSIType and SSI, so generate the SIM
                    if (tokens.length == 4) {
                        final String newSim = generateInternalSimString(tokens[0], tokens[1], tokens[2], tokens[3]);
                        san = san.replace(sim, newSim);
                    } else if (tokens.length == 3) {
                        // NOOP, it was already in the SIM format
                    } else {
                        throw new IllegalArgumentException("Wrong SIM input string with " + tokens.length + " tokens.");
                    }
                }
            }
        }
        return san;
    }

    /**
     * Creates a '::' separated string of hashAlogrithmOidString, Authority Random (R) and Privacy-Enhanced Protected Subject Information (PEPSI). 
     * Note: RFC4683 Subject Identification Method (SIM = R || PEPSI), and PEPSI = H(H( P || R || SIItype || SII)). The resulting String is used 
     * for internal storage.
     * 
     * Where R is the Authority Random hash and PEPSI the Privacy-Enhanced Protected Subject Information:
     * PEPSI = H(H( P || R || SIItype || SII))
     * Where P is the user chosen password, SSI the Sensitive Identification Information and SIIType its type.
     * 
     * @param hashAlogrithmOidString i.e '1.3.14.3.2.26' for SHA-1
     * @param userChosenPassword a user selected password for computing the SIM (see https://tools.ietf.org/html/rfc4683#section-4.2).
     * @param siiType OID string of an SSI type (see https://tools.ietf.org/html/rfc4683#section-4.1).
     * @param sii Sensitive Identification Information (SII) (see https://tools.ietf.org/html/rfc4683#section-4.1).
     * @return a '::' separated string of hashAlogrithmOidString, R and PEPSI.
     * @throws IllegalArgumentException if input is bad
     */
    public static final String generateInternalSimString(final String hashAlogrithmOidString, final String userChosenPassword, final String siiType,
            final String sii) throws IllegalArgumentException, NoSuchProviderException, NoSuchAlgorithmException {
        if (StringUtils.isBlank(hashAlogrithmOidString)) {
            throw new IllegalArgumentException("Hash algorithm OID string must not be null or empty: '" + hashAlogrithmOidString + "'.");
        }
        if (!getAllowedHashAlgorithmOidStrings().contains(hashAlogrithmOidString)) {
            throw new IllegalArgumentException("Hash algorithm with OID '" + hashAlogrithmOidString + "' is not supparted for RFC4683 (SIM).");
        }
        // To ensure that we follow the rules in RFC4683 section 5.2, the input should be enforce, it is not done here
        // hence it will in theory be possible to violate RFC4683 by illegal characters
        // See RFC4683 section 4.2: (P) FIPS 112 and FIPS 180-1 compliant password up to 28 characters
        if (StringUtils.isBlank(userChosenPassword) || userChosenPassword.length() < 8) {
            throw new IllegalArgumentException("The password must not be null, empty or only whitespace, and must be at least 8 characters.");
        }
        if (StringUtils.isBlank(siiType)) {
            throw new IllegalArgumentException("The sensitve identification information type must not be null or empty: '" + siiType + "'.");
        }
        // Throws IllegalArgumentException if ssiType is not an OID
        final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(siiType);
        if (LOG.isTraceEnabled()) {
            LOG.trace("SIIType: " + oid.getId());
        }
        if (StringUtils.isBlank(sii)) {
            throw new IllegalArgumentException("The sensitve identification information must not be null or empty: '" + sii + "'.");
        }
        final StringBuilder result = new StringBuilder();
        result.append(hashAlogrithmOidString);

        // 1. Create Digest algorithm
        final MessageDigest digester = MessageDigest.getInstance(new ASN1ObjectIdentifier(hashAlogrithmOidString).getId(),BouncyCastleProvider.PROVIDER_NAME);

        // 2. Create authority random, the same length as hash, RFC4683 section 4.3
        // Use a BC hybrid (FIPS/SP800 compliant) DRBG chain if ca.rngalgorithm is provided and it's defined as BCSP800Hybrid
        // create the seed material source - note can only be used to seed others. More info at HybridSecureRandom below.
        final SecureRandom random = new SecureRandom();
        byte[] authorityRandom = new byte[digester.getDigestLength()]; 
        random.nextBytes(authorityRandom);
        final String authorityRandomHex = Hex.toHexString(authorityRandom).toUpperCase();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authority random created: " + authorityRandomHex);
        }
        result.append(LIST_SEPARATOR).append(authorityRandomHex);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authority random hash created: " + authorityRandomHex);
        }

        // 3. Create PEPSI.
        try {
            final String pepsi = createPepsi(hashAlogrithmOidString, userChosenPassword, siiType, sii, authorityRandomHex);
            if (LOG.isDebugEnabled()) {
                LOG.debug("SIM string PEPSI created: " + pepsi);
            }
            result.append(LIST_SEPARATOR).append(pepsi);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to ASN.1 encode PEPSI input, some input is invalid: ", e);
        }
        return result.toString();
    }

    public static final String createPepsi(final String hashAlogrithmOidString, final String userChosenPassword, final String siiType,
            final String sii, final String authorityRandomHex) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {

        // Get digester for the specified hash algo
        final MessageDigest digester = MessageDigest.getInstance(new ASN1ObjectIdentifier(hashAlogrithmOidString).getId(), BouncyCastleProvider.PROVIDER_NAME);

        // Create the ASN.1 HashContent, RFC4683 5.2
        final ASN1EncodableVector v = new ASN1EncodableVector();
        // To ensure that we follow the rules in RFC4683 section 5.2, the input should be enforce, it is not done here
        // hence it will be possible to violate RFC4683 by illegal characters
        v.add(new DERUTF8String(userChosenPassword)); 
        v.add(new DEROctetString(Hex.decode(authorityRandomHex)));
        v.add(new ASN1ObjectIdentifier(siiType));
        v.add(new DERUTF8String(sii));
        final ASN1Sequence seq = new DERSequence(v);
        
        // Digest twice
        digester.update(seq.getEncoded());
        digester.update(digester.digest());
        final String pepsi = Hex.toHexString(digester.digest()).toUpperCase();
        if (LOG.isDebugEnabled()) {
            LOG.debug("SIM string PEPSI created: " + pepsi);
        }
        return pepsi;
    }

    /**
     * Creates a SIM GeneralName by the internal SIM storage format ('hashAlgorithmOIDString::R::PEPSI')
     * SIM ::= SEQUENCE { hashAlg AlgorithmIdentifier, authorityRandom OCTET
     * STRING, -- RA-chosen random number -- used in computation of -- pEPSI
     * pEPSI OCTET STRING -- hash of HashContent -- with algorithm hashAlg }
     * 
     * @param hashAlogrithmOidString the OID string for the hash algorithm used to hash R and PEPSI.
     * @param authorityRandom the registration authority chosen random value, hashed with hash of hashAlogrithmOidString (see https://tools.ietf.org/html/rfc4683#section-4.3).
     * @param pepsi Privacy-Enhanced Protected Subject Information (PEPSI), with SIM = R || PEPSI.
     * @return the RFC4683 SIM GeneralName (see <a href="https://tools.ietf.org/html/rfc4683#section-4.3">RFC 4683 section 4.3</a>).
     */
    public static final ASN1Primitive createSimGeneralName(final String hashAlgorithmIdentifier, final String authorityRandom, final String pepsi) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating SIM with hash algorithem identifier " + hashAlgorithmIdentifier + ", authority random " + authorityRandom
                    + " and PEPSI " + pepsi);
        }
        final ASN1EncodableVector otherName = new ASN1EncodableVector();
        otherName.add(new ASN1ObjectIdentifier(SUBJECTIDENTIFICATIONMETHOD_OBJECTID));
        final ASN1EncodableVector simVector = new ASN1EncodableVector();
        simVector.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashAlgorithmIdentifier)));
        simVector.add(new DEROctetString((authorityRandom).getBytes()));
        simVector.add(new DEROctetString((pepsi).getBytes()));
        otherName.add(new DERTaggedObject(true, 0, new DERSequence(simVector)));
        final ASN1Primitive generalName = new DERTaggedObject(false, 0, new DERSequence(otherName));
        if (LOG.isDebugEnabled()) {
            LOG.debug("GeneralName (type 0 - OtherName) for SIM created " + generalName.toString());
        }
        return generalName;
    }

    /**
     * Helper method for getting the SIM name from SAN ASN.1 sequence.
     * 
     * @param sequence the OtherName sequence
     * @return the SIM string by the otherName.
     */
    public static String getSimStringSequence(final ASN1Sequence sequence) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Parsing RFC4683 (SIM) from SAN ASN.1 sequence: " + sequence);
        }
        String result = null;
        if (sequence != null) {
            // First in sequence is the object identifier, that we must check
            final ASN1ObjectIdentifier id = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
            if (SUBJECTIDENTIFICATIONMETHOD_OBJECTID.equals(id.getId())) {
                // Get the PermanentIdentifier sequence
                ASN1TaggedObject oobj = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
                // Due to bug in java cert.getSubjectAltName regarding OtherName, it can be tagged an extra time...
                ASN1Primitive obj = oobj.getObject();
                if (obj instanceof ASN1TaggedObject) {
                    obj = ASN1TaggedObject.getInstance(obj).getObject();
                }
                final ASN1Sequence simVector = ASN1Sequence.getInstance(obj);
                // 1. After certificate issuance the method is called with an algorithm identifier in its ASN.1 sequence.
                // 2. But after reading a stored certificate (PEM or DER) the ASN.1 sequence contains a DERSeqence instead.
                String algorithmIdentifier = null;
                if (simVector.getObjectAt(0) instanceof AlgorithmIdentifier) {
                    algorithmIdentifier = (AlgorithmIdentifier.getInstance(simVector.getObjectAt(0)).getAlgorithm().getId());
                } else {
                    final ASN1Encodable encodable = (ASN1Sequence.getInstance(simVector.getObjectAt(0)).getObjectAt(0));
                    algorithmIdentifier = encodable.toASN1Primitive().toString();
                }
                final ASN1OctetString hash = ASN1OctetString.getInstance(simVector.getObjectAt(1));
                final ASN1OctetString pepsi = ASN1OctetString.getInstance(simVector.getObjectAt(2));
                final String hashString = new String(hash.getOctets());
                final String pepsiString = new String(pepsi.getOctets());
                final StringBuilder builder = new StringBuilder();
                result = builder.append(algorithmIdentifier).append(LIST_SEPARATOR).append(hashString).append(LIST_SEPARATOR).append(pepsiString)
                        .toString();
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("SIM parsed from other name: " + result);
        }
        return result;
    }

    /** Avoid instantiation. */
    private RFC4683Tools() {
    }
}
