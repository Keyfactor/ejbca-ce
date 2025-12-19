package org.jscep.transport.request;

/**
 * This interface represents a SCEP request.
 * 
 * Once an instance of a <code>Request</code> implementation has been obtained,
 * it can be sent to a SCEP server by using an instance of
 * {@link org.jscep.transport.AbstractTransport}.
 *
 * @see org.jscep.transport.AbstractTransport#sendRequest(Request,
 *      org.jscep.transport.response.ScepResponseHandler)
 */
public abstract class Request {
    private final Operation operation;

    /**
     * Constructs a new {@code Request} for the given SCEP {@code Operation}.
     *
     * @param operation
     *            the operation to carry out.
     */
    public Request(final Operation operation) {
        this.operation = operation;
    }

    /**
     * Returns the name of this operation.
     *
     * @return the name of this operation.
     */
    public final Operation getOperation() {
        return operation;
    }

    /**
     * Returns the message for this request.
     *
     * @return the message.
     */
    public abstract String getMessage();
}
