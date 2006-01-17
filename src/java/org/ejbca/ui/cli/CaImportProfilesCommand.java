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

import java.beans.XMLDecoder;
import java.io.File;
import java.io.FileInputStream;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;



/**
 * Export profiles from the databse to XML-files.
 *
 * @version $Id: CaImportProfilesCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
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
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_ROOTCA) ||
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH) ||
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC) ||
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_HARDTOKENENC) ||
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN) ) { 
                            getOutputStream().println("Not adding fixed certificate profile '"+profilename+"'.");
                        } else {
                            if (entityprofile && profileid == SecConst.EMPTY_ENDENTITYPROFILE) {
                                getOutputStream().println("Not adding fixed entity profile '"+profilename+"'.");
                            } else {
                                // Check if the profiles already exist, cause we donät want to add them if they do
                                boolean error = false;
                                if (entityprofile) {
                                    if (getRaAdminSession().getEndEntityProfileId(administrator, profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        getOutputStream().println("Error: Entity profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    }
                                    if (getRaAdminSession().getEndEntityProfile(administrator, profileid) != null) {
                                        getOutputStream().println("Error: Entity profileid '"+profileid+"' already exist in database.");
                                        error = true;
                                    }
                                } else {
                                    if (getCertificateStoreSession().getCertificateProfileId(administrator,profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        getOutputStream().println("Error: Certificate profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    }
                                    if (getCertificateStoreSession().getCertificateProfile(administrator,profileid) != null) {
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
                                        eprofile.loadData(decoder.readObject());
                                        try{                                        
                                            getRaAdminSession().addEndEntityProfile(administrator,profileid,profilename,eprofile);
                                            getOutputStream().println("Added entity profile '"+profilename+"' to database.");
                                        }catch(EndEntityProfileExistsException eepee){  
                                            getOutputStream().println("Error: Error adding entity profile '"+profilename+"' to database.");
                                        }                                        
                                    } else {
                                        cprofile = new CertificateProfile();
                                        cprofile.loadData(decoder.readObject());
                                        try{                                        
                                            getCertificateStoreSession().addCertificateProfile(administrator,profileid,profilename,cprofile);
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
