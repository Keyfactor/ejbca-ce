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
package org.ejbca.ui.cli;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

/**
 * Used to activate the external OCSP responder.
 * 
 * @version $Id$
 * 
 */
public class OCSPActivate extends ClientToolBox {

    @Override
	protected void execute(String[] args) {
        if (args.length < 2) {
            System.out.println(args[0] + " <hostname:port>");
            System.out.println(" Used for HSM activation on an OCSP server install.");
            System.out.println(" hostname:port  the address of where the OCSP serrver is running. Only use 127.0.0.1 in a production environment.");
            return;
        }
        final String bindInfo = args[1];
        final char[] passwd;

        System.out.print("Password: ");
        passwd = System.console().readPassword();

        try {
            final URL url = new URL("http://" + bindInfo + "/ejbca/publicweb/status/ocsp");
            final HttpURLConnection con;
            {
                final URLConnection con0 = url.openConnection();
                if (con0 == null || !(con0 instanceof HttpURLConnection)) {
                    System.out.println("Unable to open http connection to " + url);
                }
                con = (HttpURLConnection) con0;
            }
            con.setRequestMethod("POST");
            con.setRequestProperty("activate", new String(passwd));
            final int responseCode = con.getResponseCode();
            if (responseCode != 200) {
                final String responseMessage = con.getResponseMessage();
                System.out.println("Unexpected result code " + responseCode + " for URL: '" + url + "'. Message was: '" + responseMessage + '\'');
                return;
            }
            System.out.println("Password for keys sent to the OCSP responder. If the password was right the responder will be activated. Check this.");
        } catch (IOException e) {
            System.out.println("Network problems: '" + e.getMessage() + '\'');
        }
    }

    @Override
    protected String getName() {
        return "OCSPActivate";
    }
}
