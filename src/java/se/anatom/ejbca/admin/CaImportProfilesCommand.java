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

import java.beans.XMLDecoder;
import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;

import javax.naming.InitialContext;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.exception.CertificateProfileExistsException;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileExistsException;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;


/**
 * Export profiles from the databse to XML-files.
 *
 * @version $Id: CaImportProfilesCommand.java,v 1.8 2004-10-13 07:14:45 anatom Exp $
 */
public class CaImportProfilesCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaImportProfilesCommand
     *
     * @param args command line arguments
     */
    public CaImportProfilesCommand(String[] args) {
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

            //InitialContext jndicontext = new InitialContext();
            InitialContext jndicontext = getInitialContext();

            Object obj1 = jndicontext.lookup("CertificateStoreSession");
            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create();

            obj1 = jndicontext.lookup("RaAdminSession");

            IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "RaAdminSession"), IRaAdminSessionHome.class);
            IRaAdminSessionRemote raadminsession = raadminsessionhome.create();



            if (args.length < 2) {
                getOutputStream().println("Usage: CA importprofiles <inpath>");
                getOutputStream().print("\n");
                return;
            }

            String inpath = args[1];

            getOutputStream().println("Importing certificate and entity profiles: ");
            File inFile = new File(inpath);
            // List all filenames in the given directory, we will try to import them all
            File[] infiles = inFile.listFiles();
            for (int i = 0; i < infiles.length; i++) {
                getOutputStream().println("Filename:"+infiles[i].getName());
                if ( infiles[i].isFile() && ((infiles[i].getName().indexOf("certprofile_") > -1) || (infiles[i].getName().indexOf("entityprofile_") > -1)) ) {
                    boolean entityprofile = false;
                    if (infiles[i].getName().indexOf("entityprofile_") > -1) {
                        entityprofile=true;
                    }
                    int index1 = infiles[i].getName().indexOf("_");
                    int index2 = infiles[i].getName().lastIndexOf("-");
                    int index3 = infiles[i].getName().lastIndexOf(".xml");
                    if (index1 < 0 || index2 < 0 || index3 < 0) {
                        getOutputStream().println("Error: Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
                    } else {
                        String profilename = infiles[i].getName().substring(index1+1,index2);
                        //getOutputStream().println("Name:"+profilename);
                        //getOutputStream().println("Id:"+infiles[i].getName().substring(index2+1,index3));
                        int profileid = Integer.parseInt(infiles[i].getName().substring(index2+1,index3));
                        // We don't add the fixed profiles, EJBCA handles those automagically
                        if ( (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_ENDUSER) || 
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_SUBCA) ||
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_ROOTCA) ) { 
                            getOutputStream().println("Not adding fixed certificate profile '"+profilename+"'.");
                        } else {
                            if (entityprofile && profileid == SecConst.EMPTY_ENDENTITYPROFILE) {
                                getOutputStream().println("Not adding fixed entity profile '"+profilename+"'.");
                            } else {
                                // Check if the profiles already exist, cause we donät want to add them if they do
                                boolean error = false;
                                if (entityprofile) {
                                    if (raadminsession.getEndEntityProfileId(administrator, profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        getOutputStream().println("Error: Entity profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    }
                                    if (raadminsession.getEndEntityProfile(administrator, profileid) != null) {
                                        getOutputStream().println("Error: Entity profileid '"+profileid+"' already exist in database.");
                                        error = true;
                                    }
                                } else {
                                    if (certificatesession.getCertificateProfileId(administrator,profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        getOutputStream().println("Error: Certificate profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    }
                                    if (certificatesession.getCertificateProfile(administrator,profileid) != null) {
                                        getOutputStream().println("Error: Certificate profile id '"+profileid+"' already exist in database.");
                                        error = true;
                                    }
                                }
                                if (!error) {
                                    CertificateProfile cprofile = null;
                                    EndEntityProfile eprofile = null;
                                    FileInputStream is = new FileInputStream(infiles[i]);
                                    XMLDecoder decoder = new XMLDecoder( is );
                                    if (entityprofile) {
                                        eprofile = new EndEntityProfile();
                                        eprofile.loadData((HashMap)decoder.readObject());
                                        try{                                        
                                           raadminsession.addEndEntityProfile(administrator,profileid,profilename,eprofile);
										   getOutputStream().println("Added entity profile '"+profilename+"' to database.");
                                        }catch(EndEntityProfileExistsException eepee){  
										  getOutputStream().println("Error: Error adding entity profile '"+profilename+"' to database.");
                                        }                                        
                                    } else {
                                        cprofile = new CertificateProfile();
                                        cprofile.loadData((HashMap)decoder.readObject());
                                        try{                                        
                                          certificatesession.addCertificateProfile(administrator,profileid,profilename,cprofile);
										  getOutputStream().println("Added certificate profile '"+profilename+"' to database.");
                                        }catch(CertificateProfileExistsException cpee){
											getOutputStream().println("Error: Error adding certificate profile '"+profilename+"' to database.");
                                        }                                          
                                    }
                                    decoder.close();
                                    is.close();
                                }
                            }
                        }
                    }
                }
            }          
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
