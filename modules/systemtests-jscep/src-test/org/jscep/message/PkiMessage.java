/*
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

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.TransactionId;

/**
 * This class represents an abstract SCEP {@code pkiMessage}, which may be
 * either a request or response.
 * 
 * @param <T>
 *            the MessageData for this message.
 */
public abstract class PkiMessage<T> {
    private final TransactionId transId;
    private final MessageType messageType;
    private final Nonce senderNonce;
    private final T messageData;

    /**
     * Creates a new {@code PkiMessage} instance.
     * 
     * @param transId
     *            the request transaction ID.
     * @param messageType
     *            the type of message represented by this instance.
     * @param senderNonce
     *            the request nonce.
     * @param messageData
     *            the data carried by this message.
     */
    public PkiMessage(final TransactionId transId,
            final MessageType messageType, final Nonce senderNonce,
            final T messageData) {
        this.transId = transId;
        this.messageType = messageType;
        this.senderNonce = senderNonce;
        this.messageData = messageData;
    }

    /**
     * The request transaction ID.
     * 
     * @return the transaction ID.
     */
    public final TransactionId getTransactionId() {
        return transId;
    }

    /**
     * The SCEP message type of this message.
     * 
     * @return the message type.
     */
    public final MessageType getMessageType() {
        return messageType;
    }

    /**
     * The nonce of the original request.
     * 
     * @return the nonce.
     */
    public final Nonce getSenderNonce() {
        return senderNonce;
    }

    /**
     * The message data contained in this message.
     * 
     * @return the message data.
     */
    public T getMessageData() {
        return messageData;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this,
                new String[] { "messageData" });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj,
                new String[] { "messageData" });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
