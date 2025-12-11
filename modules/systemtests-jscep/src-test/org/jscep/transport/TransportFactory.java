package org.jscep.transport;

import java.net.URL;

public interface TransportFactory {
    public enum Method {
        GET,
        POST
    }

    Transport forMethod(Method method, URL url);
}
