/*
 * Copyright (c) 2009-2010 David Grant
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

package org.jscep.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.message.CertRep;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkcsPkiEnvelopeDecoder;
import org.jscep.message.PkcsPkiEnvelopeEncoder;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.request.Operation;
import org.jscep.transport.response.Capability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides a base Servlet which can be extended using the abstract
 * methods to implement a SCEP CA (or RA).
 */
public abstract class ScepServlet extends HttpServlet {
    private static final String GET = "GET";
    private static final String POST = "POST";
    private static final String MSG_PARAM = "message";
    private static final String OP_PARAM = "operation";
    private static final Logger LOGGER = LoggerFactory
            .getLogger(ScepServlet.class);
    /**
     * Serialization ID
     */
    private static final long serialVersionUID = 1L;

    /**
     * {@inheritDoc}
     */
    @Override
    public final void service(final HttpServletRequest req,
            final HttpServletResponse res) throws ServletException, IOException {
        byte[] body = getMessageBytes(req);

        final Operation op;
        try {
            op = getOperation(req);
            if (op == null) {
                 // The operation parameter must be set.
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing \"operation\" parameter.");
                return;
            }
        } catch (IllegalArgumentException e) {
            // The operation was not recognised.
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid \"operation\" parameter.");
            return;
        }

        LOGGER.debug("Incoming Operation: " + op);

        final String reqMethod = req.getMethod();

        if (op == Operation.PKI_OPERATION) {
            if (!reqMethod.equals(POST) && !reqMethod.equals(GET)) {
                // PKIOperation must be sent using GET or POST

                res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                res.addHeader("Allow", GET + ", " + POST);

                return;
            }
        } else {
            if (!reqMethod.equals(GET)) {
                // Operations other than PKIOperation must be sent using GET

                res.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                res.addHeader("Allow", GET);

                return;
            }
        }

        LOGGER.debug("Method " + reqMethod + " Allowed for Operation: " + op);

        if (op == Operation.GET_CA_CAPS) {
            try {
                LOGGER.debug("Invoking doGetCaCaps");
                doGetCaCaps(req, res);
            } catch (Exception e) {
                throw new ServletException(e);
            }
        } else if (op == Operation.GET_CA_CERT) {
            try {
                LOGGER.debug("Invoking doGetCaCert");
                doGetCaCert(req, res);
            } catch (Exception e) {
                throw new ServletException(e);
            }
        } else if (op == Operation.GET_NEXT_CA_CERT) {
            try {
                LOGGER.debug("Invoking doGetNextCaCert");
                doGetNextCaCert(req, res);
            } catch (Exception e) {
                throw new ServletException(e);
            }
        } else if (op == Operation.PKI_OPERATION) {
            // PKIOperation

            res.setHeader("Content-Type", "application/x-pki-message");

            CMSSignedData sd;
            try {
                sd = new CMSSignedData(body);
            } catch (CMSException e) {
                throw new ServletException(e);
            }

            Store<X509CertificateHolder> reqStore = sd.getCertificates();
            Collection<X509CertificateHolder> reqCerts = reqStore
                    .getMatches(null);

            CertificateFactory factory;
            try {
                factory = CertificateFactory.getInstance("X.509");
            } catch (CertificateException e) {
                throw new ServletException(e);
            }
            X509CertificateHolder holder = reqCerts.iterator().next();
            ByteArrayInputStream bais = new ByteArrayInputStream(
                    holder.getEncoded());
            X509Certificate reqCert;
            try {
                reqCert = (X509Certificate) factory.generateCertificate(bais);
            } catch (CertificateException e) {
                throw new ServletException(e);
            }

            PkiMessage<?> msg;
            try {
                PkcsPkiEnvelopeDecoder envDecoder = new PkcsPkiEnvelopeDecoder(
                        getRecipient(), getRecipientKey());
                PkiMessageDecoder decoder = new PkiMessageDecoder(reqCert,
                        envDecoder);
                msg = decoder.decode(sd);
            } catch (MessageDecodingException e) {
                LOGGER.error("Error decoding request", e);
                throw new ServletException(e);
            }

            LOGGER.debug("Processing message {}", msg);

            MessageType msgType = msg.getMessageType();
            Object msgData = msg.getMessageData();

            Nonce senderNonce = Nonce.nextNonce();
            TransactionId transId = msg.getTransactionId();
            Nonce recipientNonce = msg.getSenderNonce();
            CertRep certRep;

            if (msgType == MessageType.GET_CERT) {
                final IssuerAndSerialNumber iasn = (IssuerAndSerialNumber) msgData;
                final X500Name principal = iasn.getName();
                final BigInteger serial = iasn.getSerialNumber().getValue();

                try {
                    List<X509Certificate> issued = doGetCert(principal, serial);
                    if (issued.isEmpty()) {
                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, FailInfo.badCertId);
                    } else {
                        CMSSignedData messageData = getMessageData(issued);

                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, messageData);
                    }
                } catch (OperationFailureException e) {
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                } catch (Exception e) {
                    throw new ServletException(e);
                }
            } else if (msgType == MessageType.GET_CERT_INITIAL) {
                final IssuerAndSubject ias = (IssuerAndSubject) msgData;
                final X500Name issuer = X500Name.getInstance(ias.getIssuer());
                final X500Name subject = X500Name.getInstance(ias.getSubject());

                try {
                    List<X509Certificate> issued = doGetCertInitial(issuer,
                            subject, transId);

                    if (issued.isEmpty()) {
                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce);
                    } else {
                        CMSSignedData messageData = getMessageData(issued);

                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, messageData);
                    }
                } catch (OperationFailureException e) {
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                } catch (Exception e) {
                    throw new ServletException(e);
                }
            } else if (msgType == MessageType.GET_CRL) {
                final IssuerAndSerialNumber iasn = (IssuerAndSerialNumber) msgData;
                final X500Name issuer = iasn.getName();
                final BigInteger serialNumber = iasn.getSerialNumber()
                        .getValue();

                try {
                    LOGGER.debug("Invoking doGetCrl");
                    CMSSignedData messageData = getMessageData(doGetCrl(issuer,
                            serialNumber));

                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            messageData);
                } catch (OperationFailureException e) {
                    LOGGER.error("Error executing GetCRL request", e);
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                } catch (Exception e) {
                    LOGGER.error("Error executing GetCRL request", e);
                    throw new ServletException(e);
                }
            } else if (msgType == MessageType.PKCS_REQ) {
                final PKCS10CertificationRequest certReq = (PKCS10CertificationRequest) msgData;

                try {
                    LOGGER.debug("Invoking doEnrol");
                    List<X509Certificate> issued = doEnrol(certReq, reqCert, transId);

                    if (issued.isEmpty()) {
                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce);
                    } else {
                        CMSSignedData messageData = getMessageData(issued);

                        certRep = new CertRep(transId, senderNonce,
                                recipientNonce, messageData);
                    }
                } catch (OperationFailureException e) {
                    certRep = new CertRep(transId, senderNonce, recipientNonce,
                            e.getFailInfo());
                } catch (Exception e) {
                    throw new ServletException(e);
                }
            } else {
                throw new ServletException("Unknown Message for Operation");
            }

            PkcsPkiEnvelopeEncoder envEncoder = new PkcsPkiEnvelopeEncoder(
                    reqCert, "DESede");
            PkiMessageEncoder encoder = new PkiMessageEncoder(getSignerKey(),
                    getSigner(), getSignerCertificateChain(), envEncoder);
            CMSSignedData signedData;
            try {
                signedData = encoder.encode(certRep);
            } catch (MessageEncodingException e) {
                LOGGER.error("Error decoding response", e);
                throw new ServletException(e);
            }

            res.getOutputStream().write(signedData.getEncoded());
            res.getOutputStream().close();
        } else {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Unknown Operation");
        }
    }

    private CMSSignedData getMessageData(final List<X509Certificate> certs)
            throws IOException, CMSException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        JcaCertStore store;
        try {
            store = new JcaCertStore(certs);
        } catch (CertificateEncodingException e) {
            IOException ioe = new IOException();
            ioe.initCause(e);

            throw ioe;
        }
        generator.addCertificates(store);
        return generator.generate(new CMSAbsentContent());
    }

    private CMSSignedData getMessageData(final X509CRL crl) throws CMSException,
            GeneralSecurityException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        JcaCRLStore store;
        if (crl == null) {
            store = new JcaCRLStore(Collections.emptyList());
        } else {
            store = new JcaCRLStore(Collections.singleton(crl));
        }
        generator.addCRLs(store);
        return generator.generate(new CMSAbsentContent());
    }

    private void doGetNextCaCert(final HttpServletRequest req,
            final HttpServletResponse res) throws Exception {
        res.setHeader("Content-Type", "application/x-x509-next-ca-cert");

        List<X509Certificate> certs = getNextCaCertificate(req
                .getParameter(MSG_PARAM));

        if (certs.isEmpty()) {
            res.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED,
                    "GetNextCACert Not Supported");
        } else {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCertStore store;
            try {
                store = new JcaCertStore(certs);
            } catch (CertificateEncodingException e) {
                IOException ioe = new IOException();
                ioe.initCause(e);

                throw ioe;
            }
            generator.addCertificates(store);
            DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder()
                    .build();
            SignerInfoGeneratorBuilder infoGenBuilder = new SignerInfoGeneratorBuilder(
                    digestProvider);
            X509CertificateHolder certHolder = new X509CertificateHolder(
                    getRecipient().getEncoded());
            ContentSigner contentSigner = new JcaContentSignerBuilder(
                    "SHA1withRSA").build(getRecipientKey());
            SignerInfoGenerator infoGen = infoGenBuilder.build(contentSigner,
                    certHolder);
            generator.addSignerInfoGenerator(infoGen);

            CMSSignedData degenerateSd = generator
                    .generate(new CMSAbsentContent());
            byte[] bytes = degenerateSd.getEncoded();

            res.getOutputStream().write(bytes);
            res.getOutputStream().close();
        }
    }

    private void doGetCaCert(final HttpServletRequest req,
            final HttpServletResponse res) throws Exception {
        final List<X509Certificate> certs = doGetCaCertificate(req
                .getParameter(MSG_PARAM));
        final byte[] bytes;
        if (certs.isEmpty()) {
            res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "GetCaCert failed to obtain CA from store");
            bytes = new byte[0];
        } else if (certs.size() == 1) {
            res.setHeader("Content-Type", "application/x-x509-ca-cert");
            bytes = certs.get(0).getEncoded();
        } else {
            res.setHeader("Content-Type", "application/x-x509-ca-ra-cert");
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            JcaCertStore store;
            try {
                store = new JcaCertStore(certs);
            } catch (CertificateEncodingException e) {
                IOException ioe = new IOException();
                ioe.initCause(e);

                throw ioe;
            }
            generator.addCertificates(store);
            CMSSignedData degenerateSd = generator
                    .generate(new CMSAbsentContent());
            bytes = degenerateSd.getEncoded();
        }

        res.getOutputStream().write(bytes);
        res.getOutputStream().close();
    }

    private Operation getOperation(final HttpServletRequest req) {
        String op = req.getParameter(OP_PARAM);
        if (op == null) {
            return null;
        }
        return Operation.forName(req.getParameter(OP_PARAM));
    }

    private void doGetCaCaps(final HttpServletRequest req,
            final HttpServletResponse res) throws Exception {
        res.setHeader("Content-Type", "text/plain");
        final Set<Capability> caps = doCapabilities(req.getParameter(MSG_PARAM));
        for (Capability cap : caps) {
            res.getWriter().write(cap.toString());
            res.getWriter().write('\n');
        }
        res.getWriter().close();
    }

    /**
     * Returns the capabilities of the specified CA.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @return the capabilities.
     * @throws Exception
     *             if any problem occurs
     */
    protected abstract Set<Capability> doCapabilities(final String identifier)
            throws Exception;

    /**
     * Returns the certificate chain of the specified CA.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @return the CA's certificate.
     * @throws Exception
     *             if any problem occurs
     */
    protected abstract List<X509Certificate> doGetCaCertificate(
            String identifier) throws Exception;

    /**
     * Return the chain of the next X.509 certificate which will be used by the
     * specified CA.
     *
     * @param identifier
     *            the CA identifier, which may be an empty string.
     * @return the list of certificates.
     * @throws Exception
     *             if any problem occurs
     */
    protected abstract List<X509Certificate> getNextCaCertificate(
            String identifier) throws Exception;

    /**
     * Retrieve the certificate chain identified by the given parameters.
     *
     * @param issuer
     *            the issuer name.
     * @param serial
     *            the serial number.
     * @return the identified certificate, if any.
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    protected abstract List<X509Certificate> doGetCert(final X500Name issuer,
            final BigInteger serial) throws Exception;

    /**
     * Checks to see if a previously-requested certificate has been issued. If
     * the certificate has been issued, this method will return the appropriate
     * certificate chain. Otherwise, this method should return null or an empty
     * list to indicate that the request is still pending.
     *
     * @param issuer
     *            the issuer name.
     * @param subject
     *            the subject name.
     * @param transId
     *            the transaction ID.
     * @return the identified certificate, if any.
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    protected abstract List<X509Certificate> doGetCertInitial(
            final X500Name issuer, final X500Name subject,
            final TransactionId transId) throws Exception;

    /**
     * Retrieve the CRL covering the given certificate identifiers.
     *
     * @param issuer
     *            the certificate issuer.
     * @param serial
     *            the certificate serial number.
     * @return the CRL.
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    protected abstract X509CRL doGetCrl(final X500Name issuer,
            final BigInteger serial) throws Exception;

    /**
     * Enrols a certificate into the PKI represented by this SCEP interface. If
     * the request can be completed immediately, this method returns an
     * appropriate certificate chain. If the request is pending, this method
     * should return null or any empty list.
     *
     * @param certificationRequest
     *            the PKCS #10 CertificationRequest
     * @param transId
     *            the transaction ID
     * @param sender
     *            the sender of the certificate
     * @return the certificate chain, if any
     * @throws OperationFailureException
     *             if the operation cannot be completed
     * @throws Exception
     *             if any problem occurs
     */
    protected abstract List<X509Certificate> doEnrol(
            final PKCS10CertificationRequest certificationRequest,
            final X509Certificate sender,
            final TransactionId transId) throws Exception;

    /**
     * Returns the private key of the recipient entity represented by this SCEP
     * server.
     *
     * @return the private key.
     */
    protected abstract PrivateKey getRecipientKey();

    /**
     * Returns the certificate of the server recipient entity.
     *
     * @return the certificate.
     */
    protected abstract X509Certificate getRecipient();

    /**
     * Returns the private key of the entity represented by this SCEP server.
     *
     * @return the private key.
     */
    protected abstract PrivateKey getSignerKey();

    /**
     * Returns the certificate of the entity represented by this SCEP server.
     *
     * @return the certificate.
     */
    protected abstract X509Certificate getSigner();

    /**
     * Returns the certificate chain of the entity represented by this SCEP server.
     *
     * @return the chain
     */
    protected abstract X509Certificate[] getSignerCertificateChain();

    private byte[] getMessageBytes(final HttpServletRequest req)
            throws IOException {
        if (req.getMethod().equals(POST)) {
            return IOUtils.toByteArray(req.getInputStream());
        } else {
            final Operation op;
            try {
                op = getOperation(req);
            } catch (IllegalArgumentException e) {
               // Assume the caller also calls getOperation and deals with this
               // failure.  For us return the same body we do for non-pki
               // operations.
               return new byte[0];
            }

            if (op == Operation.PKI_OPERATION) {
                String msg = req.getParameter(MSG_PARAM);
                if (msg.length() == 0) {
                    return new byte[0];
                }
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Decoding {}", msg);
                }
                return Base64.decode(fixBrokenBase64(msg));
            } else {
                return new byte[0];
            }
        }
    }

    /**
     * iOS 11's MDM sends badly encoded Base64 data, with '+' encoded as ' '.
     *
     * @return the base64 string with ' ' replaced by '+'.
     */
    private String fixBrokenBase64(String base64) {
        return base64.replace(' ', '+');
    }

}
