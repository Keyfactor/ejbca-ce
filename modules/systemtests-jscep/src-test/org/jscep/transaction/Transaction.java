package org.jscep.transaction;

import java.security.cert.CertStore;

import org.bouncycastle.cms.CMSSignedData;
import org.jscep.message.CertRep;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkiMessage;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.transport.Transport;
import org.jscep.transport.TransportException;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.PkiOperationResponseHandler;
import org.jscep.util.SignedDataUtils;

/**
 * This class represents an abstract SCEP transaction.
 */
public abstract class Transaction {
    private final PkiMessageEncoder encoder;
    private final PkiMessageDecoder decoder;
    private final Transport transport;

    private State state;
    private FailInfo failInfo;
    private CertStore certStore;

    /**
     * Constructs a new {@code Transaction}.
     *
     * @param transport
     *            the transport used to conduct the transaction.
     * @param encoder
     *            the encoder used to encode the request.
     * @param decoder
     *            the decoder used to decode the response.
     */
    public Transaction(final Transport transport,
            final PkiMessageEncoder encoder, final PkiMessageDecoder decoder) {
        this.transport = transport;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    /**
     * Retrieve the reason for failure.
     * <p>
     * If the transaction did not fail, this method throws an
     * {@link IllegalStateException}.
     *
     * @return the reason for failure.
     */
    public final FailInfo getFailInfo() {
        if (state != State.CERT_NON_EXISTANT) {
            throw new IllegalStateException(
                    "No failure has been received.  Check state!");
        }
        return failInfo;
    }

    /**
     * Retrieve the {@code CertStore} sent by the SCEP server.
     * <p>
     * If the transaction did not succeed, this method throws an
     * {@link IllegalStateException}
     *
     * @return the {@code CertStore}
     */
    public final CertStore getCertStore() {
        if (state != State.CERT_ISSUED) {
            throw new IllegalStateException(
                    "No certstore has been received.  Check state!");
        }
        return certStore;
    }

    /**
     * Sends the request and processes the server response.
     *
     * @return the state as return by the SCEP server.
     * @throws TransactionException
     *             if an error was encountered when sending this transaction.
     */
    public abstract State send() throws TransactionException;

    /**
     * Returns the ID of this transaction.
     *
     * @return the ID of this transaction.
     */
    public abstract TransactionId getId();

    final CMSSignedData send(final PkiOperationResponseHandler handler,
            final Request req) throws TransactionException {
        try {
            return transport.sendRequest(req, handler);
        } catch (TransportException e) {
            throw new TransactionException(e);
        }
    }

    final PkiMessage<?> decode(final CMSSignedData res)
            throws MessageDecodingException {
        return decoder.decode(res);
    }

    final CMSSignedData encode(final PkiMessage<?> message)
            throws MessageEncodingException {
        return encoder.encode(message);
    }

    final State pending() {
        this.state = State.CERT_REQ_PENDING;
        return state;
    }

    final State failure(final FailInfo failInfo) {
        this.failInfo = failInfo;
        this.state = State.CERT_NON_EXISTANT;

        return state;
    }

    final State success(final CertStore certStore) {
        this.certStore = certStore;
        this.state = State.CERT_ISSUED;

        return state;
    }

    final CertStore extractCertStore(final CertRep response) {
        CMSSignedData signedData = response.getMessageData();

        return SignedDataUtils.fromSignedData(signedData);
    }

    /**
     * This class represents the state of a transaction.
     */
    public enum State {
        /**
         * The transaction is a pending state.
         */
        CERT_REQ_PENDING,
        /**
         * The transaction is in a failed state.
         * 
         * Clients should use {@link Transaction#getFailInfo()} to retrieve the
         * failure reason.
         */
        CERT_NON_EXISTANT,
        /**
         * The transaction has succeeded.
         *
         * Clients should use {@link Transaction#getCertStore()} to retrieve the
         * enrolled certificates.
         */
        CERT_ISSUED,
    }
}
