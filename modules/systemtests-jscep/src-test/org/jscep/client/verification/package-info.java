/**
 * Provides an interface and several implementation classes for verifying the identity of a certificate.
 * <p>
 * Classes in this package should be combined with {@link org.jscep.client.CertificateVerificationCallback} for verifying
 * the certificate sent from the SCEP server in {@code GetCaCert} requests.  The SCEP specification recommends that one 
 * {@code GetCaCert} request is made before each operation, so this package will be used quite frequently.
 */
package org.jscep.client.verification;

