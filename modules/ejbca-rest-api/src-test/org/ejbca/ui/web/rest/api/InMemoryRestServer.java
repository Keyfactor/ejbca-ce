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

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.ejbca.ui.web.rest.api.config.ExceptionHandler;
import org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver;

import javax.ws.rs.client.Client;
import  javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Application;

import org.jboss.resteasy.plugins.server.undertow.UndertowJaxrsServer;

/**
 * A wrapper utility that creates an instance of TJWSEmbeddedJaxrsServer to run Unit Tests on top of the Resteasy embedded server.
 * <br/>
 * By default this server registers these providers:
 * <ul>
 * <li>ExceptionHandler - handles an exception;</li>
 * <li>ObjectMapperContextResolver - defines the mapping for JSON.</li>
 * </ul>
 *
 * @see org.ejbca.ui.web.rest.api.config.ExceptionHandler
 */
public class InMemoryRestServer implements AutoCloseable {

    private static final String bindAddress = "localhost";
    private final Set<Object> resources = new HashSet<>();
    private UndertowJaxrsServer server;
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

    class TestApplication extends Application {
        @Override
        public Set<Class<?>> getClasses() {
            final Set<Class<?>> clazzes = new HashSet<>();
            clazzes.add(ExceptionHandler.class);
            clazzes.add(ObjectMapperContextResolver.class);
            return clazzes;
        }

        @Override
        public Set<Object> getSingletons() {
            return resources;
        }
    }
    /**
     * Starts the server instance locally on localhost using dynamic port with predefined SecurityDomain and resources.
     *
     * @throws IOException in case of ServerSocket failure.
     */
    public void start() throws IOException {
        server = new UndertowJaxrsServer();
        port = findFreePort();
        server.setPort(port);
        server.setHostname(bindAddress);
        server.deploy(new TestApplication());
        server.start();
    }

    /**
     * Forms an endpoint's request denoted by URI.
     * <br/>
     * For example newRequest("/v1/ca") forms the request on URL "http://localhost:8080/v1/ca".
     *
     * @param uriPath a part of URL to make request on.
     * @return An instance of ClientRequest.
     */
    public WebTarget newRequest(final String uriPath) {
        Client client = ClientBuilder.newClient();
        final WebTarget target = client.target("http://" + bindAddress + ":" + port + uriPath);
        return target;
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
