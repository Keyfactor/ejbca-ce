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

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

public class GetProfileCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

   private static final int ARG_PROFILE_ID = 1;
   private static final int ARG_PROFILE_TYPE = 2;
   private static final int ARG_DESTINATION_DIRECTORY = 3;

   GetProfileCommand(String[] args) {
       super(args);
   }

   @Override
   public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
       try {
           if(args.length !=  4){
               usage();
               System.exit(-1); // NOPMD, it's not a JEE app
           }

           int profileid = Integer.parseInt(args[ARG_PROFILE_ID]);
           
           // Read and validate the profile type
           String profiletype = args[ARG_PROFILE_TYPE];
           if(!StringUtils.equalsIgnoreCase(profiletype, "eep") && !StringUtils.equalsIgnoreCase(profiletype, "cp")) {
               getPrintStream().println("Error: Unknown profile type. Accepted types are 'eep' for end entity profiles and 'cp' for certificate profiles.");
               return;
           }
           
           // Read and verify that the path is to a directory
           String directory = args[ARG_DESTINATION_DIRECTORY];
           File dir = new File(directory);
           if(!dir.exists() || !dir.isDirectory()) {
               getPrintStream().println("Error: The specified directory is either not a directory or it does not exist");
               return;
           }


           byte[] profile;
           try {
               profile = getEjbcaRAWS().getProfile(profileid, profiletype);

               final String outfile = directory + "/" + profiletype + "-" + profileid + ".xml";
               FileOutputStream out = new FileOutputStream(outfile);
               out.write(profile);
               out.close();
               getPrintStream().println("Profile exported to " + outfile);
           } catch (AuthorizationDeniedException_Exception e) {
               getPrintStream().println("Error : " + e.getMessage());
           } catch (EjbcaException_Exception e) {
               getPrintStream().println("Error : " + e.getMessage());
           }
       } catch (NumberFormatException e) {
           getPrintStream().println("Error: The profileID should be a number");
       } catch (Exception e) {
           throw new ErrorAdminCommandException(e);
       }
   }

   @Override
   protected void usage() {
       getPrintStream().println("Command used to retrieve a specific end entity or certificate profile userdata");
       getPrintStream().println("Usage : getprofile <profileid> <profiletype> <destdirectory>\n");
       getPrintStream().print("Profile type can be either 'eep' for End Entity Profiles or 'cp' for Certificate Profiles");
   }
}