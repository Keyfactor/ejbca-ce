package org.jscep.transport.request;

/**
 * This class represents a <code>GetNextCACert</code> request.
 */
public final class GetNextCaCertRequest extends Request {
    private final String profile;

    /**
     * Creates a new {@code GetNextCaCertRequest} with the given CA profile.
     * 
     * @param profile
     *            the CA profile to use.
     */
    public GetNextCaCertRequest(final String profile) {
        super(Operation.GET_NEXT_CA_CERT);
        this.profile = profile;
    }

    /**
     * Creates a new {@code GetNextCaCertRequest} without a CA profile.
     */
    public GetNextCaCertRequest() {
        this(null);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getMessage() {
        if (profile == null) {
            return "";
        }
        return profile;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        if (profile != null) {
            return "GetNextCACert(" + profile + ")";
        } else {
            return "GetNextCACert";
        }
    }
}
