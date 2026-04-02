package org.jscep.transport;

import javax.net.ssl.SSLSocketFactory;
import java.net.URL;

public class UrlConnectionTransportFactory implements TransportFactory {

    private SSLSocketFactory sslSocketFactory;

    public UrlConnectionTransportFactory(){}

    public UrlConnectionTransportFactory(SSLSocketFactory sslSocketFactory){
        this.sslSocketFactory = sslSocketFactory;
    }

    @Override
    public Transport forMethod(Method method, URL url) {
        if (method == Method.GET) {
            return new UrlConnectionGetTransport(url, sslSocketFactory);
        } else {
            return new UrlConnectionPostTransport(url, sslSocketFactory);
        }
    }
}
