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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * This command performs a simple health check call and prints the output to the console. 
 * 
 * @version $Id$
 *
 */
public class HealthCheck extends ClientToolBox {

    @Override
    protected void execute(String[] args) {
        final String httpPath;
        if (args.length < 2) {
            System.out.println(args[0] + " <http URL>");
            System.out.println("Example: healthCheck http://localhost:8080/ejbca/publicweb/healthcheck/ejbcahealth");
            return;
        }
        httpPath = args[1];
        final URL url;
        try {
            url = new URL(httpPath);
        } catch (MalformedURLException e) {
            System.err.println("URL " + httpPath + " was not a correctly formed URL.");
            System.exit(-1);
            return;
        }
        final HttpURLConnection con;
        try {
           con = (HttpURLConnection) url.openConnection();
           System.out.println("Response code was " + con.getResponseCode());
           InputStream content = (InputStream) con.getContent();
           final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
           while (true) {
               int nextByte = content.read();
               if (nextByte < 0) {
                   break;
               }
               byteArrayOutputStream.write(nextByte);
           }
           System.out.println("Response message was " + byteArrayOutputStream.toString());
        } catch (IOException e) {
            System.err.println("Could not open connection to " + httpPath + " . Error was: " + e.getMessage());
            System.exit(-1);
            return;
        }

    }

    @Override
    protected String getName() {
        return "healthCheck";
    }

}
