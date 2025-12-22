package org.jscep.client;

import java.security.cert.CertStore;

import org.jscep.transaction.FailInfo;
import org.jscep.transaction.TransactionId;

/**
 * This class represents an enrollment response from a SCEP server.
 */
public final class EnrollmentResponse {
    /**
     * The failure info for failed responses.
     */
    private final FailInfo failInfo;
    /**
     * The CertStore for successful responses.
     */
    private final CertStore certStore;
    /**
     * The transaction ID for the current exchange.
     */
    private final TransactionId transId;

    /**
     * Constructs a new instance of this class to represent a pending response.
     * 
     * @param transId
     *            the transaction ID
     */
    public EnrollmentResponse(final TransactionId transId) {
        this(transId, null, null);
    }

    /**
     * Constructs a new instance of this class to represent a failure response.
     * 
     * @param transId
     *            the transaction ID
     * @param failInfo
     *            the failure reason
     */
    public EnrollmentResponse(final TransactionId transId,
            final FailInfo failInfo) {
        this(transId, null, failInfo);
    }

    /**
     * Constructs a new instance of this class to represent a success response.
     * 
     * @param transId
     *            the transaction ID
     * @param certStore
     *            the certificate response
     */
    public EnrollmentResponse(final TransactionId transId,
            final CertStore certStore) {
        this(transId, certStore, null);
    }

    /**
     * Constructs a new {@code EnrollmentResponse} for all cases.
     * 
     * @param transId
     *            the transactionID.
     * @param certStore
     *            the certificate response.
     * @param failInfo
     *            the failure reason.
     */
    private EnrollmentResponse(final TransactionId transId,
            final CertStore certStore, final FailInfo failInfo) {
        this.transId = transId;
        this.certStore = certStore;
        this.failInfo = failInfo;
    }

    /**
     * Returns {@code true} for a pending response, {@code false} otherwise.
     * 
     * @return {@code true} for a pending response, {@code false} otherwise.
     */
    public boolean isPending() {
        return failInfo == null && certStore == null;
    }

    /**
     * Returns {@code true} for a failure response, {@code false} otherwise.
     * 
     * @return {@code true} for a failure response, {@code false} otherwise.
     */
    public boolean isFailure() {
        return failInfo != null;
    }

    /**
     * Returns {@code true} for a success response, {@code false} otherwise.
     * 
     * @return {@code true} for a success response, {@code false} otherwise.
     */
    public boolean isSuccess() {
        return certStore != null;
    }

    /**
     * Returns the transaction ID for the enrollment operation.
     * 
     * @return the transaction ID.
     */
    public TransactionId getTransactionId() {
        return transId;
    }

    /**
     * Returns the CertStore for a successful enrollment.
     * <p>
     * If this method is invoked on a non-success response, this method will
     * throw an {@link IllegalStateException}
     * 
     * @return the CertStore.
     */
    public CertStore getCertStore() {
        if (isSuccess()) {
            return certStore;
        }
        throw new IllegalStateException();
    }

    /**
     * Returns the failure reason for a failed enrollment.
     * <p>
     * If this method is invoked on a non-failure response, this method will
     * throw an {@link IllegalStateException}
     * 
     * @return the failure reason.
     */
    public FailInfo getFailInfo() {
        if (isFailure()) {
            return failInfo;
        }
        throw new IllegalStateException();
    }

}
