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
 
package org.ejbca.core.protocol.ws.client;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Finds a certificates in the database
 *
 * @version $Id: FindCertsCommand.java 19902 2014-09-30 14:32:24Z anatom $
 */
public class GetExpiredCertificatesByIssuerCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

    
    private static final int ARG_DAYS                  = 1;
    private static final int ARG_ISSUER                = 2;
    private static final int ARG_MAX_NUMBER_OF_RESULTS = 3;  
    private static final int ARG_ENCODING              = 4;
    private static final int ARG_OUTPUTPATH            = 5;
    
    public GetExpiredCertificatesByIssuerCommand(String[] args) {
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
           
            if(args.length <  6){
                usage();
                System.exit(-1); // NOPMD, it's not a JEE app
            }
            
            long days = Long.parseLong(args[ARG_DAYS]);
            String issuerDN = args[ARG_ISSUER];
            int maxNumberOfResults = Integer.parseInt(args[ARG_MAX_NUMBER_OF_RESULTS]);
            String encoding = getEncoding(args[ARG_ENCODING]);
            String outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
            
            
            try{
                List<Certificate> result = getEjbcaRAWS().getCertificatesByExpirationTimeAndIssuer(days, issuerDN, maxNumberOfResults);
                
                if(result==null || result.size() == 0){
                    getPrintStream().println("No certificate will expire within " + days + " days and are issued by " + issuerDN);
                }else{
                    getPrintStream().println(result.size() + " certificate found, written to " + outputPath);
                    Iterator<Certificate> iter = result.iterator();
                    int i=0;
                    while(iter.hasNext()){
                        i++;
                        Certificate cert = iter.next();
                        if(encoding.equals("DER")){
                            FileOutputStream fos = new FileOutputStream(outputPath + "/" + "cert-" + i +".cer");
                            fos.write(CertificateHelper.getCertificate(cert.getCertificateData()).getEncoded());
                            fos.close();
                        }else{
                            FileOutputStream fos = new FileOutputStream(outputPath + "/" + "cert-" + i +".pem");
                            ArrayList<java.security.cert.Certificate> list = new ArrayList<java.security.cert.Certificate>();
                            list.add(CertificateHelper.getCertificate(cert.getCertificateData()));
                            fos.write(CertTools.getPemFromCertificateChain(list));
                            fos.close();                                                        
                        }                        
                    }
                }
                             
            }catch(AuthorizationDeniedException_Exception e){
                getPrintStream().println("Error : " + e.getMessage());
            }           
        } catch (Exception e) {
            ErrorAdminCommandException adminexp = new ErrorAdminCommandException(e);
            getPrintStream().println("Error: " + adminexp.getLocalizedMessage());
        }
    }

    private String getOutputPath(String outputpath) {
        File dir = new File(outputpath);
        if(!dir.exists()){
            getPrintStream().println("Error : Output directory doesn't seem to exist.");
            System.exit(-1); // NOPMD, it's not a JEE app
        }
        if(!dir.isDirectory()){
            getPrintStream().println("Error : Output directory doesn't seem to be a directory.");
            System.exit(-1); // NOPMD, it's not a JEE app           
        }
        if(!dir.canWrite()){
            getPrintStream().println("Error : Output directory isn't writeable.");
            System.exit(-1); // NOPMD, it's not a JEE app

        }
        return outputpath;
    }

    private String getEncoding(String encoding) {
        if(!encoding.equalsIgnoreCase("PEM") && !encoding.equalsIgnoreCase("DER")){
            usage();
            System.exit(-1); // NOPMD, it's not a JEE app
        }
        
        return encoding.toUpperCase();
    }

    protected void usage() {
        getPrintStream().println("Command used to find certificates that will expire within a specified number of days and are issued by a specific CA");
        getPrintStream().println("Usage : getexpiredcertsbyissuer <numberOfDays> <issuerDN> <maxNumberOfResults> <encoding (DER|PEM)> <outputpath>");
        getPrintStream().println();
        getPrintStream().println("maxNumberOfResults: the maximum number of returned certificates");
        getPrintStream().println("outputpath : directory where certificates are written");
        getPrintStream().println("Note that all returned certificates are of status active or notified about expiration");
   }


}
