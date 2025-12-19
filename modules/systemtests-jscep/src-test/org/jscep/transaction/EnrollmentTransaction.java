package org.jscep.transaction;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.message.CertRep;
import org.jscep.message.GetCertInitial;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkcsReq;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.message.PkiRequest;
import org.jscep.transport.Transport;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.jscep.util.CertificationRequestUtils;
import org.slf4j.Logger;

/**
 * This class represents a SCEP enrollment transaction.
 * 
 * @see PkcsReq
 * @see GetCertInitial
 */
public final class EnrollmentTransaction extends Transaction {
    private static final Logger LOGGER = getLogger(EnrollmentTransaction.class);
    private static final NonceQueue QUEUE = new NonceQueue();
    private final TransactionId transId;
    private final PkiRequest<?> request;

    /**
     * Constructs a new transaction for enrollment request.
     * 
     * @param transport
     *            the transport to use to send the transaction request.
     * @param encoder
     *            the encoder to encode the transaction request.
     * @param decoder
     *            the decoder to decode the transaction response.
     * @param csr
     *            the signing request to send.
     * @throws TransactionException
     *             if there is a problem creating the transaction ID.
     */
    public EnrollmentTransaction(final Transport transport,
            final PkiMessageEncoder encoder, final PkiMessageDecoder decoder,
            final PKCS10CertificationRequest csr) throws TransactionException {
        super(transport, encoder, decoder);
        try {
            this.transId = TransactionId.createTransactionId(
                    CertificationRequestUtils.getPublicKey(csr), "SHA-1");
        } catch (IOException e) {
            throw new TransactionException(e);
        }
        this.request = new PkcsReq(transId, Nonce.nextNonce(), csr);
    }

    /**
     * Constructs a new transaction for a enrollment poll request.
     * 
     * @param transport
     *            the transport to use to send the transaction request.
     * @param encoder
     *            the encoder to encode the transaction request.
     * @param decoder
     *            the decoder to decode the transaction response.
     * @param ias
     *            the issuer and subject to send.
     * @param transId
     *            the transaction ID to use.
     */
    public EnrollmentTransaction(final Transport transport,
            final PkiMessageEncoder encoder, final PkiMessageDecoder decoder,
            final IssuerAndSubject ias, final TransactionId transId) {
        super(transport, encoder, decoder);

        this.transId = transId;
        this.request = new GetCertInitial(transId, Nonce.nextNonce(), ias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TransactionId getId() {
        return transId;
    }

    /**
     * Sends the request to the SCEP server and processes the response..
     * 
     * @return the transaction state as returned by the SCEP server.
     * @throws TransactionException
     *             if any transaction-related error occurs.
     */
    @Override
    public State send() throws TransactionException {
        CMSSignedData signedData;
        try {
            signedData = encode(request);
        } catch (MessageEncodingException e) {
            throw new TransactionException(e);
        }
        LOGGER.debug("Sending {}", signedData);
        PkiOperationResponseHandler handler = new PkiOperationResponseHandler();
        CMSSignedData res = send(handler, new PkiOperationRequest(signedData));
        LOGGER.debug("Received response {}", res);

        CertRep response;
        try {
            response = (CertRep) decode(res);
        } catch (MessageDecodingException e) {
            throw new TransactionException(e);
        }
        validateExchange(request, response);

        LOGGER.debug("Response: {}", response);

        if (response.getPkiStatus() == PkiStatus.FAILURE) {
            return failure(response.getFailInfo());
        } else if (response.getPkiStatus() == PkiStatus.SUCCESS) {
            return success(extractCertStore(response));
        } else {
            return pending();
        }
    }

    private void validateExchange(final PkiMessage<?> req, final CertRep res)
            throws TransactionException {
        LOGGER.debug("Validating SCEP message exchange");

        if (!res.getTransactionId().equals(req.getTransactionId())) {
            throw new TransactionException("Transaction ID Mismatch");
        } else {
            LOGGER.debug("Matched transaction IDs");
        }

        // The requester SHOULD verify that the recipientNonce of the reply
        // matches the senderNonce it sent in the request.
        if (!res.getRecipientNonce().equals(req.getSenderNonce())) {
            throw new InvalidNonceException(req.getSenderNonce(),
                    res.getRecipientNonce());
        } else {
            LOGGER.debug("Matched request senderNonce and response recipientNonce");
        }

        if (res.getSenderNonce() == null) {
            LOGGER.warn("Response senderNonce is null");
            return;
        }

        // http://tools.ietf.org/html/draft-nourse-scep-20#section-8.5
        // Check that the nonce has not been encountered before.
        if (QUEUE.contains(res.getSenderNonce())) {
            throw new InvalidNonceException(res.getSenderNonce());
        } else {
            QUEUE.add(res.getSenderNonce());
            LOGGER.debug("{} has not been encountered before",
                    res.getSenderNonce());
        }

        LOGGER.debug("SCEP message exchange validated successfully");
    }
}
