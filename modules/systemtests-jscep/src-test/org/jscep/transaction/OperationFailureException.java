package org.jscep.transaction;

import net.jcip.annotations.Immutable;

/**
 * Represents a failure encountered when attempting to perform a SCEP operation.
 */
@Immutable
public final class OperationFailureException extends TransactionException {
    private static final long serialVersionUID = 326478648151473741L;
    private final FailInfo failInfo;

    /**
     * Creates a new {@code OperationFailureException} based on the given
     * {@code FailInfo}.
     * 
     * @param failInfo
     *            the reason for failure.
     */
    public OperationFailureException(final FailInfo failInfo) {
        super("Operation failed due to " + failInfo);
        this.failInfo = failInfo;
    }

    /**
     * Returns the {@code failInfo} that caused this exception.
     * 
     * @return the {@code failInfo}
     */
    public FailInfo getFailInfo() {
        return failInfo;
    }
}
