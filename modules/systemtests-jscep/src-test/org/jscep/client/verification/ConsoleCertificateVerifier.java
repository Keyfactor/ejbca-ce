package org.jscep.client.verification;

import static java.security.Security.getAlgorithms;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Scanner;

import org.apache.commons.codec.binary.Hex;

/**
 * This {@code CertificateVerifier} uses the system console to determine
 * verification.
 * <p>
 * Implementors should use this if they require interactive certificate
 * verification in a command line application.
 */
public final class ConsoleCertificateVerifier implements CertificateVerifier {

    /**
     * Use the system console to prompt the user with each available hash.
     * 
     * @param cert
     *            the certificate to verify
     * @return {@code true} if the certificate is verified, {@code false}
     *         otherwise.
     */
    @Override
    public boolean verify(final X509Certificate cert) {
        final List<String> algs = new ArrayList<String>(
                getAlgorithms(MessageDigest.class.getSimpleName()));
        Collections.sort(algs);
        int max = 0;
        for (final String alg : algs) {
            if (alg.length() > max) {
                max = alg.length();
            }
        }
        for (final String alg : algs) {
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(alg);
            } catch (NoSuchAlgorithmException e) {
                return false;
            }
            byte[] hash;
            try {
                hash = digest.digest(cert.getEncoded());
            } catch (CertificateEncodingException e) {
                return false;
            }
            System.out.format("%" + max + "s: %s%n", alg,
                    Hex.encodeHexString(hash));
        }
        final Scanner scanner = new Scanner(System.in, Charset.defaultCharset()
                .name()).useDelimiter(String.format("%n"));
        while (true) {
            System.out.format("%nAccept? (Y/N): [N]%n");
            try {
                final String answer = scanner.next();
                System.out.println(answer);
                if (answer.equals("Y")) {
                    return true;
                } else if (answer.equals("N")) {
                    return false;
                }
            } catch (final NoSuchElementException e) {
                return false;
            }
        }
    }

}
