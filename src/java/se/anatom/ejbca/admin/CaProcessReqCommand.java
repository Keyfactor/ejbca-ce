/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.admin;

import java.io.*;
import java.security.cert.X509Certificate;

import javax.naming.Context;

import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.protocol.PKCS10RequestMessage;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.FileTools;


/**
 * Receive certification request and create certificate to send back.
 *
 * @version $Id: CaProcessReqCommand.java,v 1.12 2004-10-13 07:14:45 anatom Exp $
 */
public class CaProcessReqCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaProcessReqCommand
     *
     * @param args command line arguments
     */
    public CaProcessReqCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 5) {
                getOutputStream().println(
                    "Usage: CA processreq <username> <password> <request-file> <outfile>");
                getOutputStream().println(
                    "Used to receive certificate requests from subCAs and generate certificates to be sent back.");

                return;
            }

            String username = args[1];
            String password = args[2];
            String reqfile = args[3];
            String outfile = args[4];

            getOutputStream().println("Processing cert request:");
            getOutputStream().println("Username: " + username);
            getOutputStream().println("Password: " + password);
            getOutputStream().println("Request file: " + reqfile);

            byte[] b64Encoded = FileTools.readFiletoBuffer(reqfile);
            byte[] buffer;

            try {
                String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
                String endKey = "-----END CERTIFICATE REQUEST-----";
                buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
            } catch (IOException e) {
                String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
                String endKey = "-----END NEW CERTIFICATE REQUEST-----";
                buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
            }

            Context ctx = getInitialContext();
            ISignSessionHome home = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup(
                        "RSASignSession"), ISignSessionHome.class);
            ISignSessionRemote ss = home.create();
            PKCS10RequestMessage p10 = new PKCS10RequestMessage(buffer);
            p10.setUsername(username);
            p10.setPassword(password);
            IResponseMessage resp = ss.createCertificate(administrator, p10, Class.forName("se.anatom.ejbca.protocol.X509ResponseMessage"));
            X509Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
            FileOutputStream fos = new FileOutputStream(outfile);
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(Base64.encode(cert.getEncoded()));
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
            fos.close();
            getOutputStream().println("Wrote certificate (PEM-format) to file " + outfile);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
