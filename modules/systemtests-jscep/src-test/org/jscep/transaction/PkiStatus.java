package org.jscep.transaction;

/**
 * This class represents the SCEP <code>pkiStatus</code> attribute.
 * <p>
 * This is a more user-friendly version of {@link Transaction.State}
 */
public enum PkiStatus {
    /**
     * Request granted.
     */
    SUCCESS(0),
    /**
     * Request rejected.
     */
    FAILURE(2),
    /**
     * Request pending for manual approval.
     */
    PENDING(3);

    private final int value;

    private PkiStatus(final int value) {
        this.value = value;
    }

    /**
     * Returns the numeric identifier for this {@code pkiStatus}
     * 
     * @return the numeric identifier for this {@code pkiStatus}
     */
    public int getValue() {
        return value;
    }

    /**
     * Returns the {@code pkiStatus} for the given value.
     * <p>
     * If the value provided is not 0, 2 or 3, this method throws a
     * {@link IllegalArgumentException}.
     * 
     * @param value
     *            the {@code pkiStatus} value.
     * @return the corresponding {@code pkiStatus}
     */
    public static PkiStatus valueOf(final int value) {
        for (PkiStatus status : PkiStatus.values()) {
            if (status.getValue() == value) {
                return status;
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
