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
 
package org.ejbca.ui.cli;

import java.security.cert.X509Certificate;

import org.ejbca.core.protocol.ocsp.OCSPConstants;
import org.ejbca.core.protocol.ocsp.OCSPUnidClient;
import org.ejbca.core.protocol.ocsp.OCSPUnidResponse;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;

/**
 * Implements the OCSP simple query command line query interface
 *
 * @version $Id: Ocsp.java,v 1.1 2006-02-08 20:23:03 anatom Exp $
 */
public class Ocsp extends BaseCommand {
    /**
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {

            if ( (args.length != 5) && (args.length != 3) ) {
                System.out.println("Usage 1: OCSP KeyStoreFilename Password, OCSPUrl CertificateFileName CA-certificateFileName");
                System.out.println("Usage 2: OCSP OCSPUrl CertificateFileName CA-certificateFileName");
                System.out.println("Keystore should be a PKCS12.");
                System.out.println("OCSPUrl is like: http://127.0.0.1:8080/ejbca/publicweb/status/ocsp or https://127.0.0.1:8443/ejbca/publicweb/status/ocsp");
                System.out.println("OCSP response status is: GOOD="+OCSPConstants.OCSP_GOOD+", REVOKED="+OCSPConstants.OCSP_REVOKED+", UNKNOWN="+OCSPConstants.OCSP_UNKNOWN);
                return;
            }
            String ksfilename = null;
            String kspwd = null;
            String ocspurl = null;
            String certfilename = null;
            String cacertfilename = null;
            if (args.length == 5) {
                ksfilename = args[0];
                kspwd = args[1];
                ocspurl = args[2];
                certfilename = args[3];
                cacertfilename = args[4];            	
            }
            if (args.length == 3) {
                ocspurl = args[0];
                certfilename = args[1];
                cacertfilename = args[2];            	
            }
            CertTools.installBCProvider();
            byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(certfilename),
                    "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
            X509Certificate cert = CertTools.getCertfromByteArray(bytes);
            bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(cacertfilename),
                    "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
            X509Certificate cacert = CertTools.getCertfromByteArray(bytes);
            
            OCSPUnidClient client = new OCSPUnidClient(ksfilename, kspwd, ocspurl);
            OCSPUnidResponse response = client.lookup(cert, cacert, true);
            if (response.getErrorCode() != OCSPUnidResponse.ERROR_NO_ERROR) {
            	System.out.println("Error querying OCSP server.");
            	System.out.println("Error code is: "+response.getErrorCode());
            }
            if (response.getHttpReturnCode() != 200) {
            	System.out.println("Http return code is: "+response.getHttpReturnCode());
            }
            System.out.println("OCSP return value is: "+response.getStatus());
            if (response.getFnr() != null) {
                System.out.println("Returned Fnr is: "+response.getFnr());            	
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
