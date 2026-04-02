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
package org.jscep.message;

import org.bouncycastle.cms.CMSSignedData;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

/**
 * This class represents a {@code CertRep} {@code pkiMessage}.
 */
public final class CertRep extends PkiMessage<CMSSignedData> {
    /**
     * The recipient nonce.
     */
    private final Nonce recipientNonce;
    /**
     * The PKI status.
     */
    private final PkiStatus pkiStatus;
    /**
     * The failure reason.
     */
    private final FailInfo failInfo;

    /**
     * Creates a new CertRep to indicate the original request is in a
     * <em>success</em> state.
     * 
     * @param transId
     *            the transaction ID of the original request.
     * @param senderNonce
     *            the nonce of the original request.
     * @param recipientNonce
     *            the nonce of the response.
     * @param messageData
     *            the message data
     */
    public CertRep(final TransactionId transId, final Nonce senderNonce,
            final Nonce recipientNonce, final CMSSignedData messageData) {
        super(transId, MessageType.CERT_REP, senderNonce, messageData);
        this.recipientNonce = recipientNonce;
        this.pkiStatus = PkiStatus.SUCCESS;
        this.failInfo = null;
    }

    /**
     * Creates a new CertRep to indicate the original request is in a
     * <em>failure</em> state.
     * 
     * @param transId
     *            the transaction ID of the original request.
     * @param senderNonce
     *            the nonce of the original request.
     * @param recipientNonce
     *            the nonce of the response.
     * @param failInfo
     *            the fail info enum
     */
    public CertRep(final TransactionId transId, final Nonce senderNonce,
            final Nonce recipientNonce, final FailInfo failInfo) {
        super(transId, MessageType.CERT_REP, senderNonce, null);
        this.recipientNonce = recipientNonce;
        this.pkiStatus = PkiStatus.FAILURE;
        this.failInfo = failInfo;
    }

    /**
     * Creates a new CertRep to indicate the original request is in a
     * <em>pending</em> state.
     * 
     * @param transId
     *            the transaction ID of the original request.
     * @param senderNonce
     *            the nonce of the original request.
     * @param recipientNonce
     *            the nonce of the response.
     */
    public CertRep(final TransactionId transId, final Nonce senderNonce,
            final Nonce recipientNonce) {
        super(transId, MessageType.CERT_REP, senderNonce, null);
        this.recipientNonce = recipientNonce;
        this.pkiStatus = PkiStatus.PENDING;
        this.failInfo = null;
    }

    /**
     * @return the recipient nonce.
     */
    public Nonce getRecipientNonce() {
        return recipientNonce;
    }

    /**
     * @return the PKI status.
     */
    public PkiStatus getPkiStatus() {
        return pkiStatus;
    }

    /**
     * @return the failure reason.
     */
    public FailInfo getFailInfo() {
        if (pkiStatus != PkiStatus.FAILURE) {
            throw new IllegalStateException();
        }
        return failInfo;
    }

    @Override
    public CMSSignedData getMessageData() {
        if (pkiStatus != PkiStatus.SUCCESS) {
            throw new IllegalStateException();
        }
        return super.getMessageData();
    }
}
