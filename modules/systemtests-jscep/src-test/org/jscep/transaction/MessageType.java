package org.jscep.transaction;

/**
 * This class represents the SCEP <code>messageType</code> attribute.
 */
public enum MessageType {
    /**
     * Response to certificate or CRL request.
     */
    CERT_REP(3),
    /**
     * PKCS #10 certificate request.
     */
    PKCS_REQ(19),
    /**
     * Certificate polling in manual enrollment.
     */
    GET_CERT_INITIAL(20),
    /**
     * Retrieve a certificate.
     */
    GET_CERT(21),
    /**
     * Retrieve a CRL.
     */
    GET_CRL(22);

    private final int value;

    private MessageType(final int value) {
        this.value = value;
    }

    /**
     * Returns the protocol-specific value of this {@code messageType}
     * 
     * @return the protocol-specific value of this {@code messageType}
     */
    public int getValue() {
        return value;
    }

    /**
     * The {@code messageType} corresponding to the provided value.
     * <p>
     * If the value passed to this method is neither 3 nor 19-22 inclusive, this
     * method throws an {@link IllegalArgumentException}.
     * 
     * @param value
     *            the protocol-specific value.
     * @return the corresponding {@code messageType}
     */
    public static MessageType valueOf(final int value) {
        for (MessageType msgType : MessageType.values()) {
            if (msgType.getValue() == value) {
                return msgType;
            }
        }
        throw new IllegalArgumentException();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return name();
    }
}
