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
package org.cesecore.keybind.impl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.X509KeyManager;

import org.apache.log4j.Logger;

/**
 * Simple implementation for providing a private key and a certificate chain in SSL/TLS negotiations from the client.
 * 
 * @version $Id$
 */
public class ClientX509KeyManager implements X509KeyManager {
    
    private static final Logger log = Logger.getLogger(ClientX509KeyManager.class);
    
    private final String alias;
    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;

    public ClientX509KeyManager(final String alias, final PrivateKey privateKey, final List<X509Certificate> certificateChain) {
        this.alias = alias;
        this.privateKey = privateKey;
        if(certificateChain != null) {
            this.certificateChain = certificateChain.toArray(new X509Certificate[certificateChain.size()]);
        } else {
            this.certificateChain = null;
        }
    }
    
    @Override
    public String chooseClientAlias(final String[] keyTypes, final Principal[] issuers, final Socket socket) {
        logDebugIfEnabled(null, keyTypes, issuers, socket);
        return alias;
    }
    
    @Override
    public String chooseServerAlias(final String keyType, final Principal[] issuers, final Socket socket) {
        logDebugIfEnabled(null, new String[] {keyType}, issuers, socket);
        log.warn("Got a request for server aliases, but implementation only supports client side of TLS negotiations.");
        return null;    // We are not the server side
    }

    @Override
    public X509Certificate[] getCertificateChain(final String alias) {
        logDebugIfEnabled(alias, null, null, null);
        if (this.alias.equals(alias)) {
            return certificateChain;
        }
        return null;
    }

    @Override
    public String[] getClientAliases(final String keyType, final Principal[] issuers) {
        logDebugIfEnabled(null, new String[] {keyType}, issuers, null);
        return new String[] { alias };
    }

    @Override
    public PrivateKey getPrivateKey(final String alias) {
        logDebugIfEnabled(alias, null, null, null);
        if (this.alias.equals(alias)) {
            return privateKey;
        }
        return null;
    }

    @Override
    public String[] getServerAliases(final String keyType, final Principal[] issuers) {
        logDebugIfEnabled(null, new String[] {keyType}, issuers, null);
        log.warn("Got a request for server aliases, but implementation only supports client side of TLS negotiations.");
        return null;    // We are not server side
    }  

    /** Write debug log if enabled for any of the provided nullable arguments */
    private void logDebugIfEnabled(final String alias, final String[] keyTypes, final Principal[] issuers, final Socket socket) {
        if (log.isDebugEnabled()) {
            log.debug(Thread.currentThread().getStackTrace()[2].getMethodName() + ":");
            if (alias != null) {
                log.debug(" Alias: " + alias);
            }
            if (keyTypes != null) {
                log.debug(" KeyTypes: " + Arrays.toString(keyTypes));
            }
            if (issuers != null) {
                for (final Principal issuer : issuers) {
                    log.debug(" Issuer: " + issuer);
                }
            }
            if (socket != null) {
                log.debug(" RemoteSocketAddress: " + socket.getRemoteSocketAddress());
            }
        }
    }
}
