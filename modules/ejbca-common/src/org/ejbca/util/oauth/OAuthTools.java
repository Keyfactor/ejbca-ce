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
package org.ejbca.util.oauth;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import com.nimbusds.jose.jwk.KeyType;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.KeyTools;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import org.cesecore.authentication.oauth.OAuthPublicKey;
import org.cesecore.config.OAuthConfiguration;

/**
 * Class containing static helper methods for OAuth operations
 */
public class OAuthTools {

    private static final Logger log = Logger.getLogger(KeyTools.class);

    /** Like {@link com.keyfactor.util.keys.KeyTools#getBytesFromPublicKeyFile}, but allows certificates and JWK keys also <code>{"kid":</code>... */
    public static byte[] getBytesFromOauthKey(final byte[] bytes) throws CertificateParsingException {
        try {
            return KeyTools.getBytesFromPublicKeyFile(bytes);
        } catch (CertificateParsingException originalException) {
            if (bytes.length == 0) {
                throw originalException; // No point in parsing empty files as cert or JWK
            }
            log.debug("Could not parse key as PEM or DER, trying to parse as certificate.");
            try {
                final X509Certificate cert = CertTools.getCertfromByteArray(bytes, X509Certificate.class);
                final PublicKey publicKey = cert.getPublicKey();
                return publicKey.getEncoded();
            } catch (CertificateParsingException certException) {
                log.debug("Could not parse key as PEM, DER or certificate, trying to parse as JWK.");
                try {
                    final JWK jwk = JWK.parse(new String(bytes, StandardCharsets.US_ASCII));
                    if (jwk instanceof AsymmetricJWK) {
                        return ((AsymmetricJWK) jwk).toPublicKey().getEncoded();
                    } else {
                        throw new CertificateParsingException("Wrong type of JWK key. Expected asymmetric key (EC or RSA), got unsupported key type "
                                + jwk.getKeyType().toString());
                    }
                } catch (ParseException | JOSEException | RuntimeException jwkException) {
                    log.debug("Failed to parse key as PEM, DER, X.509 certificate or JWK. Exception stack traces follow.");
                    log.debug("PEM/DER public key parsing exception", originalException);
                    log.debug("PEM/DER certificate parsing exception", certException);
                    log.debug("JWK parsing exception", jwkException);
                    throw new CertificateParsingException("Key could neither be parsed as PEM, DER, certificate or JWK", originalException);
                }
            }
        }
    }

    /**
     * Extracts the Key ID from JWK key.
     * @param bytes Encoded public key. Do <em>not</em> use the return value from getBytesFromOauthKey, that is always in DER format.
     * @return Key ID as a string, or null on any error (e.g. non JWK key)
     */
    public static String getKeyIdFromJwkKey(final byte[] bytes) {
        try {
            final JWK jwk = JWK.parse(new String(bytes, StandardCharsets.US_ASCII));
            final String keyId = jwk.getKeyID();
            if (log.isDebugEnabled()) {
                log.debug("Extracted JWK Key ID: " + keyId);
            }
            return keyId;
        } catch (RuntimeException | ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Not a JWK key, ignoring: " + e.getMessage(), e);
            }
            return null;
        }
    }

    public static Collection<OAuthPublicKey> parseKeys(List<JWK> jwkKeys) throws JOSEException {
        Collection<OAuthPublicKey> result = new ArrayList<>();
        for (JWK jwk : jwkKeys) {
            if (jwk.getKeyType().equals(KeyType.RSA)) {
                final PublicKey publicKey = jwk.toRSAKey().toPublicKey();
                final byte[] encoded = publicKey.getEncoded();
                result.add(new OAuthPublicKey(encoded, jwk.getKeyID()));
            }
        }
        return result;
    }

    /**
     * Verifies if a given hostname is in the allowed hostname list.
     * 
     * @param hostname The hostname to verify
     * @param oAuthConfiguration The OAuth configuration containing the allowed hostname list
     * @return true if the hostname is in the allowed list or if the allowed list is empty/null, false otherwise
     */
    public static boolean isHostnameAllowed(final String hostname, final OAuthConfiguration oAuthConfiguration) {
        if (hostname == null || oAuthConfiguration == null) {
            return false;
        }

        final String[] allowedHosts = oAuthConfiguration.getAllowedOauthHosts();
        if (allowedHosts == null || allowedHosts.length == 0) {
            // If no hosts are specified, we consider all hosts allowed
            return true;
        }

        String extractedHostname = hostname;
        if (hostname.contains("://")) {
            extractedHostname = hostname.split("://")[1];
        }
        if (extractedHostname.contains("/")) {
            extractedHostname = extractedHostname.split("/")[0];
        }
        if (extractedHostname.contains(":")) {
            extractedHostname = extractedHostname.split(":")[0];
        }

        final String hostnamePart = extractedHostname;

        return Arrays.stream(allowedHosts)
                .anyMatch(allowedHost -> StringUtils.equalsIgnoreCase(allowedHost, hostnamePart));
    }

}
