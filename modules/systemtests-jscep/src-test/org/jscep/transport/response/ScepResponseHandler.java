package org.jscep.transport.response;

/**
 * This interface represents a mechanism for handling specific SCEP responses.
 * 
 * @param <T>
 *            the content handled by the handler implementation
 */
public interface ScepResponseHandler<T> {
    /**
     * Marshalls the provided byte array into the parameterized response object.
     * 
     * @param response
     *            the content.
     * @param mimeType
     *            the type of the response received.
     * @return the content in a usage form.
     * @throws ContentException
     *             if any error occurs marshalling the response.
     */
    T getResponse(byte[] response, String mimeType) throws ContentException;
}
