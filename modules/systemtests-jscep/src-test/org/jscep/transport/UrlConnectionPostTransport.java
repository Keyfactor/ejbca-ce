package org.jscep.transport;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;

import net.jcip.annotations.ThreadSafe;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.jscep.transport.request.PkiOperationRequest;
import org.jscep.transport.request.Request;
import org.jscep.transport.response.ScepResponseHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * AbstractTransport representing the <code>HTTP POST</code> method.
 */
@ThreadSafe
final class UrlConnectionPostTransport extends AbstractTransport {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(UrlConnectionPostTransport.class);

    private SSLSocketFactory sslSocketFactory;

    /**
     * Creates a new {@code HttpPostTransport} for the given {@code URL}.
     * 
     * @param url
     *            the {@code URL} to send {@code POST} requests to.
     */
    public UrlConnectionPostTransport(final URL url) {
        super(url);
    }

    /**
     * Creates a new {@code HttpPostTransport} for the given {@code URL}.
     *
     * @param url
     *            the {@code URL} to send {@code POST} requests to.
     * @param sslSocketFactory
     *            the sslSocketFactory to be passed along https requests
     */
    public UrlConnectionPostTransport(final URL url, final SSLSocketFactory sslSocketFactory) {
        super(url);

        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public <T> T sendRequest(final Request msg,
            final ScepResponseHandler<T> handler) throws TransportException {
        if (!PkiOperationRequest.class.isAssignableFrom(msg.getClass())) {
            throw new IllegalArgumentException(
                    "POST transport may not be used for " + msg.getOperation()
                            + " messages.");
        }

        URL url = getUrl(msg.getOperation());
        HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/octet-stream");
            if(conn instanceof HttpsURLConnection && sslSocketFactory != null){
                ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
            }
        } catch (IOException e) {
            throw new TransportException(e);
        }
        conn.setDoOutput(true);

        byte[] message;
        try {
            message = Base64.decode(msg.getMessage().getBytes(US_ASCII.name()));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        OutputStream stream = null;
        try {
            stream = new BufferedOutputStream(conn.getOutputStream());
            stream.write(message);
        } catch (IOException e) {
            throw new TransportException(e);
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException e) {
                    LOGGER.error("Failed to close output stream", e);
                }
            }
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
            throw new TransportException("Error connecting to server.", e);
        }

        byte[] response;
        try {
            response = IOUtils.toByteArray(conn.getInputStream());
        } catch (IOException e) {
            throw new TransportException("Error reading response stream", e);
        }

        return handler.getResponse(response, conn.getContentType());
    }
}
