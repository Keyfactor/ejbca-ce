package org.ejbca.ui.web.rest.api;

import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.plugins.server.embedded.SecurityDomain;
import org.jboss.resteasy.plugins.server.tjws.TJWSEmbeddedJaxrsServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

// TODO Javadoc
public class InMemoryRestServer implements AutoCloseable {

    private Set<Object> resources = new HashSet<>();

    private TJWSEmbeddedJaxrsServer server;
    private SecurityDomain securityDomain;
    private int port;
    private static final String bindAddress = "localhost";

    private InMemoryRestServer(final SecurityDomain securityDomain, final Object... resources) {
        this.securityDomain = securityDomain;
        Collections.addAll(this.resources, resources);
    }

    public static InMemoryRestServer create(final Object... resources) {
        return create(null, resources);
    }

    public static InMemoryRestServer create(final SecurityDomain securityDomain, Object... resources) {
        return new InMemoryRestServer(securityDomain, resources);
    }

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
        server.start();
    }

    public ClientRequest newRequest(final String uriPath) {
        return new ClientRequest("http://" + bindAddress + ":" + port + uriPath);
    }

    @Override
    public void close() {
        if (server != null) {
            server.stop();
            server = null;
        }
    }

    private static int findFreePort() throws IOException {
        final ServerSocket serverSocket = new ServerSocket(0);
        final int port = serverSocket.getLocalPort();
        serverSocket.close();
        return port;
    }
}
