/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api;

import org.ejbca.ui.web.rest.api.config.ExceptionHandler;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.plugins.server.embedded.SecurityDomain;
import org.jboss.resteasy.plugins.server.tjws.TJWSEmbeddedJaxrsServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * A wrapper utility that creates an instance of TJWSEmbeddedJaxrsServer to run Unit Tests on top of the Resteasy embedded server.
 * <br/>
 * By default this server registers ExceptionHandler Provider.
 *
 * @see org.jboss.resteasy.plugins.server.tjws.TJWSEmbeddedJaxrsServer
 * @see org.ejbca.ui.web.rest.api.config.ExceptionHandler
 *
 * @version $Id: CaInfoType.java 28909 2018-05-21 12:16:53Z andrey_s_helmes $
 */
public class InMemoryRestServer implements AutoCloseable {

    private TJWSEmbeddedJaxrsServer server;
    private static final String bindAddress = "localhost";
    private int port;
    private SecurityDomain securityDomain;
    private final Set<Object> resources = new HashSet<>();

    // Private constructor
    private InMemoryRestServer(final SecurityDomain securityDomain, final Object... resources) {
        this.securityDomain = securityDomain;
        Collections.addAll(this.resources, resources);
    }

    /**
     * Creates an instance of InMemoryRestServer with bunch of resources.
     *
     * @param resources a bunch of resources to be served on the server.
     *
     * @return an instance of InMemoryRestServer.
     */
    public static InMemoryRestServer create(final Object... resources) {
        return create(null, resources);
    }

    /**
     * Creates an instance of InMemoryRestServer with predefined SecurityDomain and bunch of resources.
     *
     * @param securityDomain
     * @param resources a bunch of resources to be served on the server.
     *
     * @see org.jboss.resteasy.plugins.server.embedded.SecurityDomain
     *
     * @return an instance of InMemoryRestServer.
     */
    public static InMemoryRestServer create(final SecurityDomain securityDomain, final Object... resources) {
        return new InMemoryRestServer(securityDomain, resources);
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
        server.setSecurityDomain(securityDomain);
        // Add resources
        for (Object resource : resources) {
            server.getDeployment().getResources().add(resource);
        }
        // Add a provider
        server.getDeployment().getProviderClasses().add(ExceptionHandler.class.getName());
        server.start();
    }

    /**
     * Forms an endpoint's request denoted by URI.
     * <br/>
     * For example newRequest("/v1/ca") forms the request on URL "http://localhost:8080/v1/ca".
     *
     * @param uriPath a part of URL to make request on.
     *
     * @return An instance of ClientRequest.
     *
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

    // Looks for a free http port to run locally
    private static int findFreePort() throws IOException {
        final ServerSocket serverSocket = new ServerSocket(0);
        final int port = serverSocket.getLocalPort();
        serverSocket.close();
        return port;
    }
}
