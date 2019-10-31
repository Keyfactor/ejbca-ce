/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificatetransparency;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.apache.commons.io.IOUtils;
import org.apache.http.ConnectionClosedException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpServerConnection;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultBHttpServerConnectionFactory;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpProcessorBuilder;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.apache.http.protocol.UriHttpRequestHandlerMapper;
import org.apache.http.ssl.SSLContexts;
import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * A mock CT Log server for use from {@link CertificateTransparencyTest}
 * 
 * @version $Id$
 */
public class CTLogTestServer {
    
    private static final Logger log = Logger.getLogger(CTLogTestServer.class);

    private final ServerSocket serverSocket;
    private final ServerThread serverThread;
    private final HttpService service;
    private final int port;

    private final String expectedMethod;
    private final String expectedUrl;
    private final String expectedContentType;
    private final String expectedContent;
    private final long responseDelay;
    private final String responseContentType;
    private final String responseContent;
    
    private byte[] lastSessionId;
    
    private static KeyStore selfSigned;

    public CTLogTestServer(final String expectedMethod, final String expectedUrl, final String expectedContentType, final String expectedContent,
            final String responseContentType, final String responseContent, final int port, final boolean tls, final long responseDelay) throws IOException {
        log.debug("Creating server on port " + port);
        
        this.expectedMethod = expectedMethod;
        this.expectedUrl = expectedUrl;
        this.expectedContentType = expectedContentType;
        this.expectedContent = expectedContent;
        this.responseDelay = responseDelay;
        this.responseContentType = responseContentType;
        this.responseContent = responseContent;
        this.port = port;

        final HttpProcessor processor = HttpProcessorBuilder.create().addAll(
            new ResponseDate(),
            new ResponseServer("TestHttpServer/1.0"),
            new ResponseConnControl(),
            new ResponseContent()).build();

        final UriHttpRequestHandlerMapper handlerMapper = new UriHttpRequestHandlerMapper();
        handlerMapper.register("*", new RequestHandler());
        
        if (tls) {
            makeSelfSignedKeyStore();
            try {
                final SSLContext sslctx = SSLContexts.custom().loadKeyMaterial(selfSigned, "foo123".toCharArray()).build();
                final SSLServerSocket ssl = (SSLServerSocket)sslctx.getServerSocketFactory().createServerSocket();
                bindToLocalhostWithReuseAddress(ssl, port);
                ssl.setEnabledCipherSuites(new String[] { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" });
                ssl.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.1", "TLSv1" });
                assertTrue(ssl.getEnableSessionCreation());
                serverSocket = ssl;
            } catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
                throw new IllegalStateException(e);
            }
        } else {
            serverSocket = new ServerSocket();
            bindToLocalhostWithReuseAddress(serverSocket, port);
        }
        service = new HttpService(processor, handlerMapper);
        serverThread = new ServerThread();
        serverThread.setDaemon(false);
        serverThread.start();
    }

    private void bindToLocalhostWithReuseAddress(final ServerSocket socket, final int port) throws IOException {
        if (socket.isBound()) {
            throw new IllegalStateException("Socket is already bound");
        }
        try {
            socket.setReuseAddress(true); // must be called before binding the socket to an address
            final InetAddress localhost = InetAddress.getByName("127.0.0.1"); // Not the same as getLocalHost, which can return the public IP address!
            socket.bind(new InetSocketAddress(localhost, port), 100);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e); // should not happen with an IP address argument
        }
    }

    private static void makeSelfSignedKeyStore() {
        if (selfSigned == null) {
            try {
                final KeyPair kp = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
                // FIXME should probably use SAN for IP address
                final X509Certificate cert = CertTools.genSelfCert("CN=127.0.0.1", 365, null, kp.getPrivate(), kp.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false);
                selfSigned = KeyTools.createJKS("server", kp.getPrivate(), "foo123", cert, null);
            } catch (KeyStoreException | InvalidAlgorithmParameterException | OperatorCreationException | CertificateException e) {
                throw new IllegalStateException(e);
            }
        }
    }
    
    public byte[] getLastTLSSessionId() {
        return lastSessionId;
    }
    
    public void clearLastTLSSessionId() {
        lastSessionId = null;
    }

    public void close() throws IOException {
        serverThread.interrupt();
        serverSocket.close(); // must be called before waiting for thread to join! 
        try {
            serverThread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        log.debug("Closed server on port " + port);
    }

    private class RequestHandler implements HttpRequestHandler {

        @Override
        public void handle(final HttpRequest req, final HttpResponse resp, final HttpContext context) throws HttpException, IOException {
            if (!req.getRequestLine().getMethod().equalsIgnoreCase(expectedMethod)) {
                // Wrong method
                throw new MethodNotSupportedException("Method not supported. Expected \"" + expectedMethod + "\".");
            } else if (!req.getRequestLine().getUri().equals(expectedUrl)) {
                // Wrong URL
                sendError(resp, 400, "URL was not the expected one. Was: " + req.getRequestLine().getUri());
            } else if (!(req instanceof HttpEntityEnclosingRequest)) {
                // Missing request body
                sendError(resp, 400, "Missing request body");
            } else {
                final HttpEntityEnclosingRequest encreq = (HttpEntityEnclosingRequest) req;
                final HttpEntity entity = encreq.getEntity();
                if (!entity.getContentType().getValue().toLowerCase().startsWith(expectedContentType)) {
                    sendError(resp, 400, "Wrong content-type of request body. Was: " + entity.getContentType().getValue());
                } else {
                    final StringWriter sw = new StringWriter();
                    IOUtils.copy(entity.getContent(), sw, StandardCharsets.UTF_8);
                    final String content = sw.toString();

                    if (!expectedContent.equalsIgnoreCase(content)) {
                        sendError(resp, 400, "Request body content does not match the expected string. Was: " + new String(Base64.encode(content.getBytes(), false), StandardCharsets.US_ASCII));
                    } else {
                        resp.addHeader("Content-Type", responseContentType);
                        resp.setEntity(new StringEntity(responseContent));
                    }
                }
            }
        }
    }

    private void sendError(final HttpResponse resp, final int code, final String message) throws UnsupportedEncodingException {
        resp.setStatusLine(resp.getStatusLine().getProtocolVersion(), code, message);
        resp.setEntity(new StringEntity(message));
    }

    private class ServerThread extends Thread { // NOPMD non-JEE code
        @Override
        public void run() {
            final ScheduledExecutorService exsvc = Executors.newScheduledThreadPool(50);
            try {
                while (true) {
                    final Socket clientSocket = serverSocket.accept();
                    exsvc.schedule(new RequestRunnable(clientSocket), responseDelay, TimeUnit.MILLISECONDS);
                }
            } catch (SocketException e) { // NOPMD assume main thread closed our socket and just exit
            } catch (IOException e) {
                // Shouldn't happen in a controlled test environment
                throw new IllegalStateException(e);
            } finally {
                exsvc.shutdownNow();
            }
        }
    }
    
    private class RequestRunnable implements Runnable {
        private final Socket clientSocket;
        
        public RequestRunnable(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }
        
        @Override
        public void run() {
            try {
                if (clientSocket instanceof SSLSocket) {
                    lastSessionId = ((SSLSocket)clientSocket).getSession().getId();
                }
                try (final HttpServerConnection conn = DefaultBHttpServerConnectionFactory.INSTANCE.createConnection(clientSocket)) {
                    try {
                        final HttpContext context = new BasicHttpContext(null);
                        service.handleRequest(conn, context);
                    } catch (ConnectionClosedException e2) { // NOPMD keep accepting connections
                        log.debug("Server got ConnectionClosedException exception (might happen during shutdown)", e2);
                    }
                }
            } catch (SocketException e) { // NOPMD assume main thread closed our socket and just exit
            } catch (IOException | HttpException e) {
                // Shouldn't happen in a controlled test environment
                throw new IllegalStateException(e);
            } finally {
                try {
                    clientSocket.close(); // close socket here also in case the getSession or createConnection would throw for some reason
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
    }

}
