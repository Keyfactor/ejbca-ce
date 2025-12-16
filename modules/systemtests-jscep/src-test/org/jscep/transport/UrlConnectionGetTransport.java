package org.jscep.transport;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import net.jcip.annotations.ThreadSafe;

import org.apache.commons.io.IOUtils;
import org.jscep.transport.request.Operation;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

/**
 * AbstractTransport representing the <code>HTTP GET</code> method
 */
@ThreadSafe
final class UrlConnectionGetTransport extends AbstractTransport {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(UrlConnectionGetTransport.class);

    private SSLSocketFactory sslSocketFactory;

    /**
     * Creates a new {@code HttpGetTransport} for the given {@code URL}.
     * 
     * @param url
     *            the {@code URL} to send {@code GET} requests to.
     */
    public UrlConnectionGetTransport(final URL url) {
        super(url);
    }

    /**
     * Creates a new {@code HttpGetTransport} for the given {@code URL}.
     *
     * @param url
     *            the {@code URL} to send {@code GET} requests to.
     * @param sslSocketFactory
     *            the sslSocketFactory to be passed along https requests
     */
    public UrlConnectionGetTransport(final URL url, final SSLSocketFactory sslSocketFactory) {
        super(url);

        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public <T> T sendRequest(final Request msg,
            final ScepResponseHandler<T> handler) throws TransportException {
        URL url = getUrl(msg.getOperation(), msg.getMessage());
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Sending {} to {}", msg, url);
        }
        HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) url.openConnection();
            if(conn instanceof HttpsURLConnection && sslSocketFactory != null){
                ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
            }
        } catch (IOException e) {
            throw new TransportException(e);
        }

        try {
            int responseCode = conn.getResponseCode();
            String responseMessage = conn.getResponseMessage();

            LOGGER.debug("Received '{} {}' when sending {} to {}",
                    varargs(responseCode, responseMessage, msg, url));
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new TransportException(responseCode + " "
                        + responseMessage);
            }
        } catch (IOException e) {
            throw new TransportException("Error connecting to server", e);
        }

        byte[] response;
        try {
            response = IOUtils.toByteArray(conn.getInputStream());
        } catch (IOException e) {
            throw new TransportException("Error reading response stream", e);
        }

        return handler.getResponse(response, conn.getContentType());
    }

    private URL getUrl(final Operation op, final String message)
            throws TransportException {
        try {
            URL opUrl = getUrl(op);
            return new URI(opUrl.getProtocol(), null, opUrl.getHost(), opUrl.getPort(), opUrl.getPath(), opUrl.getQuery() + "&message=" + message, null).toURL();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new TransportException(e);
        }
    }
}
