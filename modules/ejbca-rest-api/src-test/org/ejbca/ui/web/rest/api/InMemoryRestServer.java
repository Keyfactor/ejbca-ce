/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.ejbca.ui.web.rest.api.config.ExceptionHandler;
import org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.plugins.server.tjws.TJWSEmbeddedJaxrsServer;

/**
 * A wrapper utility that creates an instance of TJWSEmbeddedJaxrsServer to run Unit Tests on top of the Resteasy embedded server.
 * <br/>
 * By default this server registers these providers:
 * <ul>
 * <li>ExceptionHandler - handles an exception;</li>
 * <li>ObjectMapperContextResolver - defines the mapping for JSON.</li>
 * </ul>
 *
 * @version $Id: InMemoryRestServer.java 29080 2018-05-31 11:12:13Z andrey_s_helmes $
 *
 * @see org.jboss.resteasy.plugins.server.tjws.TJWSEmbeddedJaxrsServer
 * @see org.ejbca.ui.web.rest.api.config.ExceptionHandler
 */
public class InMemoryRestServer implements AutoCloseable {

    private static final String bindAddress = "localhost";
    private final Set<Object> resources = new HashSet<>();
    private TJWSEmbeddedJaxrsServer server;
    private int port;

    // Private constructor
    private InMemoryRestServer(final Object... resources) {
        Collections.addAll(this.resources, resources);
    }

    /**
     * Creates an instance of InMemoryRestServer with bunch of resources.
     *
     * @param resources a bunch of resources to be served on the server.
     * @return an instance of InMemoryRestServer.
     */
    public static InMemoryRestServer create(final Object... resources) {
        return new InMemoryRestServer(resources);
    }

    // Looks for a free http port to run locally
    private static int findFreePort() throws IOException {
        final ServerSocket serverSocket = new ServerSocket(0);
        final int port = serverSocket.getLocalPort();
        serverSocket.close();
        return port;
    }

    /**
     * Starts the server instance locally on localhost using dynamic port with predefined SecurityDomain and resources.
     *
     * @throws IOException in case of ServerSocket failure.
     */
    public void start() throws IOException {
        server = new TJWSEmbeddedJaxrsServer();
        port = findFreePort();
        server.setPort(port);
        server.setBindAddress(bindAddress);
        // Add resources
        for (Object resource : resources) {
            server.getDeployment().getResources().add(resource);
        }
        // Add providers
        server.getDeployment().getProviderClasses().addAll(
                Arrays.asList(ExceptionHandler.class.getName(), ObjectMapperContextResolver.class.getName())
        );
        server.start();
    }

    /**
     * Forms an endpoint's request denoted by URI.
     * <br/>
     * For example newRequest("/v1/ca") forms the request on URL "http://localhost:8080/v1/ca".
     *
     * @param uriPath a part of URL to make request on.
     * @return An instance of ClientRequest.
     * @see org.jboss.resteasy.client.ClientRequest
     */
    public ClientRequest newRequest(final String uriPath) {
        return new ClientRequest("http://" + bindAddress + ":" + port + uriPath);
    }

    /**
     * Closes the server instance.
     */
    @Override
    public void close() {
        if (server != null) {
            server.stop();
            server = null;
        }
    }
}
