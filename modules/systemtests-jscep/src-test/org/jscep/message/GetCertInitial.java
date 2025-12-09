package org.jscep.message;

import org.jscep.asn1.IssuerAndSubject;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

/**
 * This class represents a {@code GetCertInitial} {@code pkiMessage}, which
 * wraps an {@code IssuerAndSubject} object.
 */
public class GetCertInitial extends PkiRequest<IssuerAndSubject> {
    /**
     * Creates a new {@code GetCertInitial} request.
     * 
     * @param transId
     *            the transaction ID for this request.
     * @param senderNonce
     *            the nonce for this request.
     * @param messageData
     *            the {@code IssuerAndSubject} related to the original
     *            {@code CertificationRequest}.
     */
    public GetCertInitial(final TransactionId transId, final Nonce senderNonce,
            final IssuerAndSubject messageData) {
        super(transId, MessageType.GET_CERT_INITIAL, senderNonce, messageData);
    }
}
