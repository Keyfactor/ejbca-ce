package se.anatom.ejbca.ra;

import se.anatom.ejbca.ca.sign.ISignSessionRemote;

/**
 * Implementations of this interface creates RMI objects to be used as an
 * alternative way to access ejbca.
 */
public interface RMIFactory {


    /**
     * Try not to use this method. In the SSL client authentication it is only
     * checked whether the client certicate is signed by a root with a certificate
     * in the trusted keystore. Use some other method in the interface instead and
     * define your own trustmanager with a better check.
     *
     * @param trustedFileName name of file of the keystore of trusted root
     * certificates for clients.
     *
     * @see #startConnection(PluginTools, int, int, String, String, TrustManager[])
     */
    void startConnection(
        int registryPortRMI, int startPortRMI, String keyFileName,
        String keyStorePassword, String[] args
        ) throws Exception;
}
