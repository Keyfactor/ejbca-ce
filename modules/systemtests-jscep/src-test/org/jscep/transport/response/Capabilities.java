package org.jscep.transport.response;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Collections;
import java.util.EnumSet;

import net.jcip.annotations.Immutable;

/**
 * This class represents a set of capabilities for a particular SCEP server.
 */
@Immutable
public final class Capabilities {
    private final EnumSet<Capability> caps;

    /**
     * Constructs a new instance of this class with the specified capabilities.
     *
     * @param capabilities
     *            the capabilities.
     */
    public Capabilities(final Capability... capabilities) {
        this.caps = EnumSet.noneOf(Capability.class);
        Collections.addAll(this.caps, capabilities);

        // SCEPStandard implies AES, POSTPKIOperation, and SHA-256
        if (this.caps.contains(Capability.SCEP_STANDARD)) {
            Collections.addAll(this.caps,
                               Capability.AES,
                               Capability.POST_PKI_OPERATION,
                               Capability.SHA_256);
        }
    }

    /**
     * Returns <code>true</code> if the server supports the provided Capability,
     * <code>false</code> otherwise.
     *
     * @param capability
     *            the capability to test for.
     * @return <code>true</code> if the server supports the provided Capability,
     *         <code>false</code> otherwise.
     */
    public boolean contains(final Capability capability) {
        return caps.contains(capability);
    }

    /**
     * Returns {@code true} if POST is supported, {@code false} otherwise.
     *
     * @return {@code true} if POST is supported, {@code false} otherwise.
     */
    public boolean isPostSupported() {
        return caps.contains(Capability.POST_PKI_OPERATION);
    }

    /**
     * Returns {@code true} if retrieval of the next CA is supported,
     * {@code false} otherwise.
     *
     * @return {@code true} if retrieval of the next CA is supported,
     *         {@code false} otherwise.
     */
    public boolean isRolloverSupported() {
        return caps.contains(Capability.GET_NEXT_CA_CERT);
    }

    /**
     * Returns {@code true} if certificate renewal is supported, {@code false}
     * otherwise.
     *
     * @return {@code true} if certificate renewal is supported, {@code false}
     *         otherwise.
     */
    public boolean isRenewalSupported() {
        return caps.contains(Capability.RENEWAL);
    }

    /**
     * Returns whether certificate update is supported.
     *
     * @return {@code true} if certificate update is supported, {@code false}
     *         otherwise.
     */
    public boolean isUpdateSupported() {
        return caps.contains(Capability.UPDATE);
    }

    /**
     * Returns the strongest cipher algorithm supported by the server and
     * client.
     *
     * The algorithms are ordered thus:
     * <ol>
     * <li>AES</li>
     * <li>DESede ("Triple DES")</li>
     * <li>DES</li>
     * </ol>
     *
     * @return the strongest cipher algorithm supported by the server and
     *         client.
     */
    public String getStrongestCipher() {
        final String cipher;
        if (cipherExists("AES") && caps.contains(Capability.AES)) {
            cipher = "AES";
        } else if (cipherExists("DESede")
                   && caps.contains(Capability.TRIPLE_DES)) {
            cipher = "DESede";
        } else {
            cipher = "DES";
        }

        return cipher;
    }

    private boolean cipherExists(final String algorithm) {
        return algorithmExists("Cipher", algorithm);
    }

    private boolean algorithmExists(final String serviceType,
            final String algorithm) {
        for (Provider provider : Security.getProviders()) {
            for (Service service : provider.getServices()) {
                if (service.getType().equals(serviceType)
                        && service.getAlgorithm().equalsIgnoreCase(algorithm)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns the strongest message digest algorithm supported by the server
     * and client.
     * 
     * The algorithms are ordered thus:
     * <ol>
     * <li>SHA-512</li>
     * <li>SHA-256</li>
     * <li>SHA-1</li>
     * <li>MD5</li>
     * </ol>
     * If none of the above algorithms are supported, this method returns null.
     *
     * @return the strongest message digest algorithm supported by the server
     *         and client.
     */
    public MessageDigest getStrongestMessageDigest() {
        if (digestExists("SHA-512") && caps.contains(Capability.SHA_512)) {
            return getDigest("SHA-512");
        } else if (digestExists("SHA-256") && caps.contains(Capability.SHA_256)) {
            return getDigest("SHA-256");
        } else if (digestExists("SHA-1") && caps.contains(Capability.SHA_1)) {
            return getDigest("SHA-1");
        } else if (digestExists("MD5")) {
            return getDigest("MD5");
        }
        return null;
    }

    public String getStrongestSignatureAlgorithm() {
        if (sigExists("SHA512") && caps.contains(Capability.SHA_512)) {
            return "SHA512withRSA";
        } else if (sigExists("SHA256") && caps.contains(Capability.SHA_256)) {
            return "SHA256withRSA";
        } else if (sigExists("SHA1") && caps.contains(Capability.SHA_1)) {
            return "SHA1withRSA";
        } else if (sigExists("MD5")) {
            return "MD5withRSA";
        }
        return null;
    }

    private boolean sigExists(final String sig) {
        return (algorithmExists("Signature", sig + "withRSA")
                || algorithmExists("Signature", sig + "WithRSAEncryption"))
                && digestExists(sig);
    }

    private boolean digestExists(final String digest) {
        return algorithmExists("MessageDigest", digest)
        		|| algorithmExists("MessageDigest", digest.replaceFirst("SHA", "SHA-"));
    }

    private MessageDigest getDigest(final String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return caps.toString();
    }
}
