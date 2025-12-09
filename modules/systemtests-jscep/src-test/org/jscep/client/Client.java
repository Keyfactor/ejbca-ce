/*
 * Copyright (c) 2009-2012 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.client.inspect.CertStoreInspector;
import org.jscep.client.inspect.CertStoreInspectorFactory;
import org.jscep.client.inspect.DefaultCertStoreInspectorFactory;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.EnrollmentTransaction;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.NonEnrollmentTransaction;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.Transaction;
import org.jscep.transaction.Transaction.State;
import org.jscep.transaction.TransactionException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.jscep.transport.TransportFactory;
import org.jscep.transport.TransportFactory.Method;
import org.jscep.transport.UrlConnectionTransportFactory;
import org.jscep.transport.request.GetCaCapsRequest;
import org.jscep.transport.request.GetCaCertRequest;
import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.GetCaCapsResponseHandler;
import org.jscep.transport.response.GetCaCertResponseHandler;
import org.jscep.transport.response.GetNextCaCertResponseHandler;
import org.jscep.util.X500Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@code Client} class is used for interacting with a SCEP server.
 * <p>
 * Typical usage might look like so:
 *
 * <pre>
 * // Create the client
 * URL server = new URL(&quot;http://jscep.org/scep/pkiclient.exe&quot;);
 * CertificateVerifier verifier = new ConsoleCertificateVerifier();
 * Client client = new Client(server, verifier);
 *
 * // Invoke operations on the client.
 * client.getCaCapabilities();
 * </pre>
 *
 * Each of the operations of this class is overloaded with a profile argument to
 * support SCEP servers with multiple (or mandatory) profile names.
 */
public final class Client {
    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Client.class);

    // A requester MUST have the following information locally configured:
    //
    // 1. The Certification Authority IP address or fully qualified domain name
    // 2. The Certification Authority HTTP CGI script path
    //
    // We use a URL for this.
    private final URL url;
    // A requester MUST have the following information locally configured:
    //
    // 3. The identifying information that is used for authentication of the
    // Certification Authority in Section 4.1.1. This information MAY be
    // obtained from the user, or presented to the end user for manual
    // authorization during the protocol exchange (e.g. the user indicates
    // acceptance of a fingerprint via a user-interface element).
    //
    // We use a callback handler for this.
    private final CallbackHandler handler;
    private CertStoreInspectorFactory inspectorFactory = new DefaultCertStoreInspectorFactory();
    private TransportFactory transportFactory = new UrlConnectionTransportFactory();

	/**
     * Constructs a new {@code Client} instance using the provided
     * {@code CallbackHandler} for the provided URL.
     * <p>
     * The {@code CallbackHandler} must be able to handle
     * {@link CertificateVerificationCallback}. Unless the
     * {@code CallbackHandler} will be used to handle additional
     * {@code Callback}s, users of this class are recommended to use the
     * {@link #Client(URL, CertificateVerifier)} constructor instead.
     *
     * @param url
     *            the URL of the SCEP server.
     * @param handler
     *            the callback handler used to check the CA identity.
     */
    public Client(final URL url, final CallbackHandler handler) {
        this.url = url;
        this.handler = handler;

        validateInput();
    }

    /**
     * Constructs a new {@code Client} instance using the provided
     * {@code CertificateVerifier} for the provided URL.
     * 
     * The provided {@code CertificateVerifier} is used to verify that the
     * identity of the SCEP server matches what the client expects.
     *
     * @param url
     *            the URL of the SCEP server.
     * @param verifier
     *            the verifier used to check the CA identity.
     */
    public Client(final URL url, final CertificateVerifier verifier) {
        this.url = url;
        this.handler = new DefaultCallbackHandler(verifier);

        validateInput();
    }

    /**
     * Validates all the input to this client.
     */
    private void validateInput() {
        // Check for null values first.
        if (url == null) {
            throw new NullPointerException("URL should not be null");
        }
        if (!url.getProtocol().matches("^https?$")) {
            throw new IllegalArgumentException(
                    "URL protocol should be HTTP or HTTPS");
        }
        if (url.getRef() != null) {
            throw new IllegalArgumentException(
                    "URL should contain no reference");
        }
        if (url.getQuery() != null) {
            throw new IllegalArgumentException(
                    "URL should contain no query string");
        }
        if (handler == null) {
            throw new NullPointerException(
                    "Callback handler should not be null");
        }
    }

    // INFORMATIONAL REQUESTS

    /**
     * Retrieves the set of SCEP capabilities from the CA.
     *
     * @return the capabilities of the server.
     */
    public Capabilities getCaCapabilities() {
        // NON-TRANSACTIONAL
        return getCaCapabilities(null);
    }

    /**
     * Retrieves the capabilities of the SCEP server.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param profile
     *            the SCEP server profile.
     * @return the capabilities of the server.
     */
    public Capabilities getCaCapabilities(final String profile) {
        LOGGER.debug("Determining capabilities of SCEP server");
        // NON-TRANSACTIONAL
        final GetCaCapsRequest req = new GetCaCapsRequest(profile);
        final Transport trans = transportFactory.forMethod(Method.GET, url);
        try {
            return trans.sendRequest(req, new GetCaCapsResponseHandler());
        } catch (TransportException e) {
            LOGGER.warn("AbstractTransport problem when determining capabilities.  Using empty capabilities.");
            return new Capabilities();
        }
    }

    /**
     * Retrieves the certificates used by the SCEP server.
     * <p>
     * This method queries the server for the certificates it will use in a SCEP
     * message exchange. If the SCEP server represents a single entity, only a
     * single CA certificate will be returned. If the SCEP server supports
     * multiple entities (for example, if it uses a separate entity for signing
     * SCEP messages), additional RA certificates will also be returned.
     *
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see DefaultCertStoreInspectorFactory
     */
    public CertStore getCaCertificate() throws ClientException {
        return getCaCertificate(null);
    }

    /**
     * Retrieves the certificates used by the SCEP server.
     * <p>
     * This method queries the server for the certificates it will use in a SCEP
     * message exchange. If the SCEP server represents a single entity, only a
     * single CA certificate will be returned. If the SCEP server supports
     * multiple entities (for example, if it uses a separate entity for signing
     * SCEP messages), additional RA certificates will also be returned.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getCaCertificate(final String profile)
            throws ClientException {
        LOGGER.debug("Retrieving current CA certificate");
        // NON-TRANSACTIONAL
        // CA and RA public key distribution
        final GetCaCertRequest req = new GetCaCertRequest(profile);
        final Transport trans = transportFactory.forMethod(Method.GET, url);

        CertStore store;
        try {
            store = trans.sendRequest(req, new GetCaCertResponseHandler());
        } catch (TransportException e) {
            throw new ClientException(e);
        }
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        verifyCA(certs.getIssuer());
        verifyRA(certs.getIssuer(), certs.getRecipient());
        verifyRA(certs.getIssuer(), certs.getSigner());

        return store;
    }

    private void verifyRA(final X509Certificate ca, final X509Certificate ra)
            throws ClientException {
        LOGGER.debug("Verifying signature of RA certificate");
        if (ca.equals(ra)) {
            LOGGER.debug("RA and CA are identical");

            return;
        }
        try {
            JcaX509CertificateHolder raHolder = new JcaX509CertificateHolder(ra);

            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .build(ca);

            if (!raHolder.isSignatureValid(verifierProvider)) {
                LOGGER.debug("Signature verification failed for RA.");
                throw new ClientException("RA not issued by CA");
            } else {
                LOGGER.debug("Signature verification passed for RA.");
            }
        } catch (CertException e) {
            throw new ClientException(e);
        } catch (CertificateEncodingException e) {
            throw new ClientException(e);
        } catch (OperatorCreationException e) {
            throw new ClientException(e);
        }
    }

    /**
     * Retrieves the next certificate to be used by the CA.
     * <p>
     * This method will query the SCEP server to determine if the CA is
     * scheduled to start using a new certificate for issuing.
     *
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getRolloverCertificate() throws ClientException {
        return getRolloverCertificate(null);
    }

    /**
     * Retrieves the next certificate to be used by the CA.
     * <p>
     * This method will query the SCEP server to determine if the CA is
     * scheduled to start using a new certificate for issuing.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store.
     * @throws ClientException
     *             if any client error occurs.
     * @see CertStoreInspector
     */
    public CertStore getRolloverCertificate(final String profile)
            throws ClientException {
        LOGGER.debug("Retriving next CA certificate from CA");
        // NON-TRANSACTIONAL
        if (!getCaCapabilities(profile).isRolloverSupported()) {
            throw new UnsupportedOperationException();
        }
        final CertStore store = getCaCertificate(profile);
        // The CA or RA
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        final X509Certificate signer = certs.getSigner();

        final Transport trans = transportFactory.forMethod(Method.GET, url);
        final GetNextCaCertRequest req = new GetNextCaCertRequest(profile);

        try {
            return trans.sendRequest(req, new GetNextCaCertResponseHandler(
                    signer));
        } catch (TransportException e) {
            throw new ClientException(e);
        }
    }

    // TRANSACTIONAL

    /**
     * Returns the certificate revocation list a given issuer and serial number.
     * <p>
     * This method requests a CRL for a certificate as identified by the issuer
     * name and the certificate serial number.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param issuer
     *            the name of the certificate issuer.
     * @param serial
     *            the serial number of the certificate.
     * @return the CRL corresponding to the issuer and serial.
     * @throws ClientException
     *             if any client errors occurs.
     * @throws OperationFailureException
     *             if the request fails.
     */
    public X509CRL getRevocationList(final X509Certificate identity,
            final PrivateKey key, final X500Principal issuer,
            final BigInteger serial) throws ClientException,
            OperationFailureException {
        return getRevocationList(identity, key, issuer, serial, null);
    }

    /**
     * Returns the certificate revocation list a given issuer and serial number.
     * <p>
     * This method requests a CRL for a certificate as identified by the issuer
     * name and the certificate serial number.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param issuer
     *            the name of the certificate issuer.
     * @param serial
     *            the serial number of the certificate.
     * @param profile
     *            the SCEP server profile.
     * @return the CRL corresponding to the issuer and serial.
     * @throws ClientException
     *             if any client errors occurs.
     * @throws OperationFailureException
     *             if the request fails.
     */
    @SuppressWarnings("unchecked")
    public X509CRL getRevocationList(final X509Certificate identity,
            final PrivateKey key, final X500Principal issuer,
            final BigInteger serial, final String profile)
            throws ClientException, OperationFailureException {
        LOGGER.debug("Retriving CRL from CA");
        // TRANSACTIONAL
        // CRL query
        checkDistributionPoints(profile);

        X500Name name = X500Utils.toX500Name(issuer);
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
        Transport transport = createTransport(profile);
        final Transaction t = new NonEnrollmentTransaction(transport,
                getEncoder(identity, key, profile), getDecoder(identity, key,
                        profile), iasn, MessageType.GET_CRL);
        State state;
        try {
            state = t.send();
        } catch (TransactionException e) {
            throw new ClientException(e);
        }

        if (state == State.CERT_ISSUED) {
            try {
                Collection<X509CRL> crls = (Collection<X509CRL>) t
                        .getCertStore().getCRLs(null);
                if (crls.isEmpty()) {
                    return null;
                }
                return crls.iterator().next();
            } catch (CertStoreException e) {
                throw new RuntimeException(e);
            }
        } else if (state == State.CERT_REQ_PENDING) {
            throw new IllegalStateException();
        } else {
            throw new OperationFailureException(t.getFailInfo());
        }
    }

    private void checkDistributionPoints(final String profile)
            throws ClientException {
        CertStore store = getCaCertificate(profile);
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        final X509Certificate ca = certs.getIssuer();
        if (ca.getExtensionValue(Extension.cRLDistributionPoints.getId()) != null) {
            LOGGER.warn("CA supports distribution points");
        }
    }

    /**
     * Retrieves the certificate corresponding to the provided serial number.
     * <p>
     * This request relates only to the current CA certificate. If the CA
     * certificate has changed since the requested certificate was issued, this
     * operation will fail.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param serial
     *            the serial number of the requested certificate.
     * @return the certificate store containing the requested certificate.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the SCEP server refuses to service the request.
     */
    public CertStore getCertificate(final X509Certificate identity,
            final PrivateKey key, final BigInteger serial)
            throws ClientException, OperationFailureException {
        return getCertificate(identity, key, serial, null);
    }

    /**
     * Retrieves the certificate corresponding to the provided serial number.
     * <p>
     * This request relates only to the current CA certificate. If the CA
     * certificate has changed since the requested certificate was issued, this
     * operation will fail.
     * <p>
     * This method provides support for SCEP servers with multiple profiles.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param serial
     *            the serial number of the requested certificate.
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store containing the requested certificate.
     * @throws ClientException
     *             if any client error occurs.
     * @throws OperationFailureException
     *             if the SCEP server refuses to service the request.
     */
    public CertStore getCertificate(final X509Certificate identity,
            final PrivateKey key, final BigInteger serial, final String profile)
            throws OperationFailureException, ClientException {
        LOGGER.debug("Retriving certificate from CA");
        // TRANSACTIONAL
        // Certificate query
        final CertStore store = getCaCertificate(profile);
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        final X509Certificate ca = certs.getIssuer();

        X500Name name = X500Utils.toX500Name(ca.getSubjectX500Principal());
        IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(name, serial);
        Transport transport = createTransport(profile);
        final Transaction t = new NonEnrollmentTransaction(transport,
                getEncoder(identity, key, profile), getDecoder(identity, key,
                        profile), iasn, MessageType.GET_CERT);

        State state;
        try {
            state = t.send();
        } catch (TransactionException e) {
            throw new ClientException(e);
        }

        if (state == State.CERT_ISSUED) {
            return t.getCertStore();
        } else if (state == State.CERT_REQ_PENDING) {
            throw new IllegalStateException();
        } else {
            throw new OperationFailureException(t.getFailInfo());
        }
    }

    /**
     * Sends a CSR to the SCEP server for enrolling in a PKI.
     * <p>
     * This method enrols the provider {@code CertificationRequest} into the
     * PKI represented by the SCEP server.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param csr
     *            the CSR to enrol.
     * @return the certificate store returned by the server.
     * @throws ClientException
     *             if any client error occurs.
     * @throws TransactionException
     *             if there is a problem with the SCEP transaction.
     * @see CertStoreInspector
     */
    public EnrollmentResponse enrol(final X509Certificate identity,
            final PrivateKey key, final PKCS10CertificationRequest csr)
            throws ClientException, TransactionException {
        return enrol(identity, key, csr, null);
    }

    /**
     * Sends a CSR to the SCEP server for enrolling in a PKI.
     * <p>
     * This method enrols the provider {@code CertificationRequest} into the
     * PKI represented by the SCEP server.
     *
     * @param identity
     *            the identity of the client.
     * @param key
     *            the private key to sign the SCEP request.
     * @param csr
     *            the CSR to enrol.
     * @param profile
     *            the SCEP server profile.
     * @return the certificate store returned by the server.
     * @throws ClientException
     *             if any client error occurs.
     * @throws TransactionException
     *             if there is a problem with the SCEP transaction.
     * @see CertStoreInspector
     */
    public EnrollmentResponse enrol(final X509Certificate identity,
            final PrivateKey key, final PKCS10CertificationRequest csr,
            final String profile) throws ClientException, TransactionException {
        LOGGER.debug("Enrolling certificate with CA");

        if (isSelfSigned(identity)) {
            LOGGER.debug("Certificate is self-signed");
            X500Name csrSubject = csr.getSubject();
            X500Name idSubject = X500Utils.toX500Name(identity
                    .getSubjectX500Principal());

            if (!csrSubject.equals(idSubject)) {
                LOGGER.error("The self-signed certificate MUST use the same subject name as in the PKCS#10 request.");
            }
        }
        // TRANSACTIONAL
        // Certificate enrollment
        final Transport transport = createTransport(profile);
        PkiMessageEncoder encoder = getEncoder(identity, key, profile);
        PkiMessageDecoder decoder = getDecoder(identity, key, profile);
        final EnrollmentTransaction trans = new EnrollmentTransaction(
                transport, encoder, decoder, csr);

        try {
            MessageDigest digest = getCaCapabilities(profile)
                    .getStrongestMessageDigest();
            byte[] hash = digest.digest(csr.getEncoded());

            LOGGER.debug("{} PKCS#10 Fingerprint: [{}]", digest.getAlgorithm(),
                    new String(Hex.encodeHex(hash)));
        } catch (IOException e) {
            LOGGER.error("Error getting encoded CSR", e);
        }

        return send(trans);
    }

    private boolean isSelfSigned(final X509Certificate cert)
            throws ClientException {
        try {
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .build(holder);

            return holder.isSignatureValid(verifierProvider);
        } catch (RuntimeOperatorException e) {
            if(e.getCause() instanceof  SignatureException) {
                LOGGER.warn("SignatureException detected so we consider that the certificate is not self signed");
                return false;
            }
            throw new ClientException(e);
        } catch (Exception e) {
            throw new ClientException(e);
        }
    }

    public EnrollmentResponse poll(final X509Certificate identity,
            final PrivateKey identityKey, final X500Principal subject,
            final TransactionId transId) throws ClientException,
            TransactionException {
        return poll(identity, identityKey, subject, transId, null);
    }

    public EnrollmentResponse poll(final X509Certificate identity,
            final PrivateKey identityKey, final X500Principal subject,
            final TransactionId transId, final String profile)
            throws ClientException, TransactionException {
        final Transport transport = createTransport(profile);
        CertStore store = getCaCertificate(profile);
        CertStoreInspector certStore = inspectorFactory.getInstance(store);
        X509Certificate issuer = certStore.getIssuer();

        PkiMessageEncoder encoder = getEncoder(identity, identityKey, profile);
        PkiMessageDecoder decoder = getDecoder(identity, identityKey, profile);

        IssuerAndSubject ias = new IssuerAndSubject(X500Utils.toX500Name(issuer
                .getSubjectX500Principal()), X500Utils.toX500Name(subject));

        final EnrollmentTransaction trans = new EnrollmentTransaction(
                transport, encoder, decoder, ias, transId);
        return send(trans);
    }

    private EnrollmentResponse send(final EnrollmentTransaction trans)
            throws TransactionException {
        State s = trans.send();

        if (s == State.CERT_ISSUED) {
            return new EnrollmentResponse(trans.getId(), trans.getCertStore());
        } else if (s == State.CERT_REQ_PENDING) {
            return new EnrollmentResponse(trans.getId());
        } else {
            return new EnrollmentResponse(trans.getId(), trans.getFailInfo());
        }
    }

    private PkiMessageEncoder getEncoder(final X509Certificate identity,
            final PrivateKey priKey, final String profile)
            throws ClientException {
        CertStore store = getCaCertificate(profile);
        Capabilities caps = getCaCapabilities(profile);
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        X509Certificate recipientCertificate = certs.getRecipient();
        PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                recipientCertificate, caps.getStrongestCipher());

        String sigAlg = caps.getStrongestSignatureAlgorithm();
        return new PkiMessageEncoder(priKey, identity, envEncoder, sigAlg);
    }

    private PkiMessageDecoder getDecoder(final X509Certificate identity,
            final PrivateKey key, final String profile) throws ClientException {
        final CertStore store = getCaCertificate(profile);
        CertStoreInspector certs = inspectorFactory.getInstance(store);
        X509Certificate signer = certs.getSigner();
        PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(
                identity, key);

        return new PkiMessageDecoder(signer, envDecoder);
    }

    /**
     * Creates a new transport based on the capabilities of the server.
     *
     * @param profile
     *            profile to use for determining if HTTP POST is supported
     * @return the new transport.
     */
    private Transport createTransport(final String profile) {
        if (getCaCapabilities(profile).isPostSupported()) {
            return transportFactory.forMethod(Method.POST, url);
        } else {
            return transportFactory.forMethod(Method.GET, url);
        }
    }

    private void verifyCA(final X509Certificate cert) throws ClientException {
        CertificateVerificationCallback callback = new CertificateVerificationCallback(
                cert);
        try {
            LOGGER.debug("Requesting certificate verification.");
            Callback[] callbacks = new Callback[1];
            callbacks[0] = callback;
            handler.handle(callbacks);
        } catch (UnsupportedCallbackException e) {
            LOGGER.debug("Certificate verification failed.");
            throw new ClientException(e);
        } catch (IOException e) {
            throw new ClientException(e);
        }
        if (!callback.isVerified()) {
            LOGGER.debug("Certificate verification failed.");
            throw new ClientException(
                    "CA certificate fingerprint could not be verified.");
        } else {
            LOGGER.debug("Certificate verification passed.");
        }
    }

    public synchronized void setCertStoreInspectorFactory(
            final CertStoreInspectorFactory inspectorFactory) {
        this.inspectorFactory = inspectorFactory;
    }

    public synchronized void setTransportFactory(
    		final TransportFactory transportFactory) {
    	this.transportFactory = transportFactory;
    }
}
