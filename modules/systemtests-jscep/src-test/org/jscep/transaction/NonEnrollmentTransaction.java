package org.jscep.transaction;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.message.CertRep;
import org.jscep.message.GetCert;
import org.jscep.message.GetCrl;
import org.jscep.message.MessageDecodingException;
import org.jscep.message.MessageEncodingException;
import org.jscep.message.PkiMessageDecoder;
import org.jscep.message.PkiMessageEncoder;
import org.jscep.message.PkiRequest;
import org.jscep.transport.Transport;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.response.PkiOperationResponseHandler;

/**
 * This class represents a SCEP non-enrollment {@code Transaction}.
 * 
 * @see GetCert
 * @see GetCrl
 */
public final class NonEnrollmentTransaction extends Transaction {
    private final TransactionId transId;
    private final PkiRequest<? extends ASN1Encodable> request;

    /**
     * Creates a new {@code NonEnrollmentTransaction} for the provided message.
     * <p>
     * This constructor will throw a {@link IllegalArgumentException} if invoked
     * with an inappropriate message type.
     * 
     * @param transport
     *            the transport method to use.
     * @param encoder
     *            the request encoder.
     * @param decoder
     *            the response decoder.
     * @param iasn
     *            the message to send.
     * @param msgType
     *            the type of message.
     */
    public NonEnrollmentTransaction(final Transport transport,
            final PkiMessageEncoder encoder, final PkiMessageDecoder decoder,
            final IssuerAndSerialNumber iasn, final MessageType msgType) {
        super(transport, encoder, decoder);
        this.transId = TransactionId.createTransactionId();

        if (msgType == MessageType.GET_CERT) {
            this.request = new GetCert(transId, Nonce.nextNonce(), iasn);
        } else if (msgType == MessageType.GET_CRL) {
            this.request = new GetCrl(transId, Nonce.nextNonce(), iasn);
        } else {
            throw new IllegalArgumentException(msgType.toString());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TransactionId getId() {
        return transId;
    }

    /**
     * Sends the request and processes the server response.
     * <p>
     * If the server returns a pending response, this method will throw a
     * {@code TransactionException}, since this is unexpected behaviour.
     * 
     * @return the state as returned by the SCEP server.
     * @throws TransactionException
     *             if an error was encountered when sending this transaction.
     */
    @Override
    public State send() throws TransactionException {
        final PkiOperationResponseHandler handler = new PkiOperationResponseHandler();
        CMSSignedData signedData;
        try {
            signedData = encode(request);
        } catch (MessageEncodingException e) {
            throw new TransactionException(e);
        }

        CMSSignedData res = send(handler, new PkiOperationRequest(signedData));
        CertRep response;
        try {
            response = (CertRep) decode(res);
        } catch (MessageDecodingException e) {
            throw new TransactionException(e);
        }

        if (response.getPkiStatus() == PkiStatus.FAILURE) {
            return failure(response.getFailInfo());
        } else if (response.getPkiStatus() == PkiStatus.SUCCESS) {
            return success(extractCertStore(response));
        } else {
            throw new TransactionException("Invalid Response");
        }
    }
}
