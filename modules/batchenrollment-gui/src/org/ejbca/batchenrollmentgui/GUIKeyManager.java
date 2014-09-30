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
package org.ejbca.batchenrollmentgui;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;
import javax.swing.JOptionPane;

/**
 * Key manager that prompts user for choosing which certificate to use.
 *
 * @author markus
 * @version $Id$
 */
public class GUIKeyManager implements X509KeyManager {

    private final X509KeyManager base;

    public GUIKeyManager(final X509KeyManager base) {
        this.base = base;
    }

    public String[] getClientAliases(String string, Principal[] prncpls) {
        return base.getClientAliases(string, prncpls);
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        // For each keyType, call getClientAliases on the base KeyManager
        // to find valid aliases. If our requested alias is found, select it
        // for return.
        String selectedAlias = null;
        for (int i = 0; i < keyType.length; i++) {
            String[] validAliases = base.getClientAliases(keyType[i], issuers);
            if (validAliases != null) {
                selectedAlias = (String) JOptionPane.showInputDialog(null, "Choose identity:", "Login", JOptionPane.DEFAULT_OPTION, null, validAliases, validAliases[0]);
                if (selectedAlias != null) {
                    break;
                }
            }
        }
        return selectedAlias;
    }

    public String[] getServerAliases(String string, Principal[] prncpls) {
        return base.getClientAliases(string, prncpls);
    }

    public String chooseServerAlias(String string, Principal[] prncpls, Socket socket) {
        return base.chooseServerAlias(string, prncpls, socket);
    }

    public X509Certificate[] getCertificateChain(String string) {
        return base.getCertificateChain(string);
    }

    public PrivateKey getPrivateKey(String string) {
        return base.getPrivateKey(string);
    }
}
