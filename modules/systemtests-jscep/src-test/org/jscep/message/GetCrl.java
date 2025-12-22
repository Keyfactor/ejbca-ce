package org.jscep.message;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

/**
 * This class represents a {@code GetCRL} {@code pkiMessage}, which wraps an
 * {@code IssuerAndSerialNumber} object.
 */
public class GetCrl extends PkiRequest<IssuerAndSerialNumber> {
    /**
     * Creates a new {@code GetCrl} instance.
     * 
     * @param transId
     *            the transaction ID for this request.
     * @param senderNonce
     *            the nonce for this request.
     * @param messageData
     *            the {@code IssuerAndSerialNumber} of the certificate
     *            referenced by the CRL.
     */
    public GetCrl(final TransactionId transId, final Nonce senderNonce,
            final IssuerAndSerialNumber messageData) {
        super(transId, MessageType.GET_CRL, senderNonce, messageData);
    }
}
