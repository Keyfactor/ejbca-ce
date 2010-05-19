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
 
package org.ejbca.ui.cli.ca;

import java.beans.XMLDecoder;
import java.io.File;
import java.io.FileInputStream;
import java.util.Collection;
import java.util.HashMap;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.FileTools;

/**
 * Import profiles from XML-files to the database.
 *
 * @version $Id$
 */
public class CaImportProfilesCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importprofiles"; }
	public String getDescription() { return "Import profiles from XML-files to the database"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 2) {
        		getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <inpath> [<CAName>]");
                return;
            }
            String inpath = args[1];
            Integer caid = null;
            if (args.length > 2) {
            	CAInfo ca = getCAAdminSession().getCAInfo(getAdmin(), args[2]);
            	if (ca != null) {
            		caid = ca.getCAId();
            	} else {
            		getLogger().error("CA '"+args[2]+"' does not exist.");
                    return;
            	}
            }
            HashMap<Integer, Integer> certificateProfileIdMapping = new HashMap<Integer, Integer>();
            getLogger().info("Importing certificate and end entity profiles: ");
            File inFile = new File(inpath);
            if (!inFile.isDirectory()) {
            	getLogger().error("'"+inpath+"' is not a directory.");
                return;
            }
            // List all filenames in the given directory, we will try to import them all
            File[] infiles = inFile.listFiles();
            FileTools.sortByName(infiles);
            for (int i = 0; i < infiles.length; i++) {
            	getLogger().info("Filename: "+infiles[i].getName());
                if ( infiles[i].isFile() && ((infiles[i].getName().indexOf("certprofile_") > -1) || (infiles[i].getName().indexOf("entityprofile_") > -1)) ) {
                    boolean entityprofile = false;
                    if (infiles[i].getName().indexOf("entityprofile_") > -1) {
                        entityprofile=true;
                    }
                    int index1 = infiles[i].getName().indexOf("_");
                    int index2 = infiles[i].getName().lastIndexOf("-");
                    int index3 = infiles[i].getName().lastIndexOf(".xml");
                    if (index1 < 0 || index2 < 0 || index3 < 0) {
                    	getLogger().error("Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
                    } else {
                        String profilename = infiles[i].getName().substring(index1+1,index2);
                        //getLogger().debug("Name:"+profilename);
                        //getLogger().debug("Id:"+infiles[i].getName().substring(index2+1,index3));
                        int profileid = Integer.parseInt(infiles[i].getName().substring(index2+1,index3));
                        // We don't add the fixed profiles, EJBCA handles those automagically
                        if ( !entityprofile && SecConst.isFixedCertificateProfile(profileid) ) { 
                        	getLogger().error("Not adding fixed certificate profile '"+profilename+"'.");
                        } else {
                            if (entityprofile && profileid == SecConst.EMPTY_ENDENTITYPROFILE) {
                            	getLogger().error("Not adding fixed entity profile '"+profilename+"'.");
                            } else {
                                // Check if the profiles already exist, and change the name and id if already taken
                                boolean error = false;
                                if (entityprofile) {
                                    if (getRaAdminSession().getEndEntityProfileId(getAdmin(), profilename) != SecConst.PROFILE_NO_PROFILE) {
                                    	getLogger().error("Entity profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    } else if (getRaAdminSession().getEndEntityProfile(getAdmin(), profileid) != null) {
                                        int newprofileid = getRaAdminSession().findFreeEndEntityProfileId();
                                        getLogger().warn("Entity profileid '"+profileid+"' already exist in database. Using " + newprofileid + " instead.");
                                        profileid = newprofileid;
                                    }
                                } else {
                                    if (getCertificateStoreSession().getCertificateProfileId(getAdmin(),profilename) != SecConst.PROFILE_NO_PROFILE) {
                                    	getLogger().error("Error: Certificate profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    } else if (getCertificateStoreSession().getCertificateProfile(getAdmin(),profileid) != null) {
                                    	int newprofileid  = getCertificateStoreSession().findFreeCertificateProfileId();
                                    	getLogger().warn("Certificate profile id '"+profileid+"' already exist in database. Using " + newprofileid + " instead.");
                                        certificateProfileIdMapping.put(profileid, newprofileid);
                                        profileid = newprofileid;
                                    }
                                }
                                if (!error) {
                                    EndEntityProfile eprofile = null;
                                    FileInputStream is = new FileInputStream(infiles[i]);
                                    XMLDecoder decoder = new XMLDecoder( is );
                                    if (entityprofile) {
                                        eprofile = new EndEntityProfile();
                                        eprofile.loadData(decoder.readObject());
                                        
                                        //Set the end entity profile to work with any CA
                                        eprofile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
                                        eprofile.setRequired(EndEntityProfile.DEFAULTCA,0,true);
                                        
                                        // Translate cert profile ids that have changed after import
                                        String availableCertProfiles = "";
                                        String defaultCertProfile = eprofile.getValue(EndEntityProfile.DEFAULTCERTPROFILE,0);
                                    	//getLogger().debug("Debug: Org - AVAILCERTPROFILES " + eprofile.getValue(EndEntityProfile.AVAILCERTPROFILES,0) + " DEFAULTCERTPROFILE "+defaultCertProfile);
                                        for (String currentCertProfile : (Collection<String>) eprofile.getAvailableCertificateProfileIds()) {
                                        	Integer currentCertProfileId = Integer.parseInt(currentCertProfile);
                                        	Integer replacementCertProfileId = certificateProfileIdMapping.get(currentCertProfileId);
                                        	if ( replacementCertProfileId != null ) {
                                        		if (!replacementCertProfileId.toString().equals(currentCertProfile)) {
                                        			getLogger().warn("Replacing cert profile with id "+currentCertProfile+" with " + replacementCertProfileId + ".");
                                        		}
                                        		availableCertProfiles += (availableCertProfiles.equals("") ? "" : ";" ) + replacementCertProfileId;
                                        		if (currentCertProfile.equals(defaultCertProfile)) {
                                        			defaultCertProfile = ""+replacementCertProfileId;
                                        		}
                                        	} else {
                                        		if (getCertificateStoreSession().getCertificateProfile(getAdmin(), currentCertProfileId) != null ||
                                        				SecConst.isFixedCertificateProfile(currentCertProfileId)) {
                                            		availableCertProfiles += (availableCertProfiles.equals("") ? "" : ";" ) + currentCertProfile;
                                       			} else {
                                       				getLogger().warn("End Entity Profile '"+profilename+"' references certificate profile " + currentCertProfile + " that does not exist.");
                                            		if (currentCertProfile.equals(defaultCertProfile)) {
                                            			defaultCertProfile = "";
                                            		}
                                       			}
                                        	}
                                        }
                                        if (availableCertProfiles.equals("")) {
                                        	getLogger().warn("End Entity Profile only references certificate profile(s) that does not exist. Using ENDUSER profile.");
                                            availableCertProfiles = "1"; // At least make sure the default profile is available
                                        }
                                        if (defaultCertProfile.equals("")) {
                                        	defaultCertProfile = availableCertProfiles.split(";")[0];	// Use first available profile from list as default if original default was missing
                                        }
                                        
                                    	//getOutputStream().println("Debug: New - AVAILCERTPROFILES " + availableCertProfiles + " DEFAULTCERTPROFILE "+defaultCertProfile);
                                        eprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, availableCertProfiles);
                                        eprofile.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, defaultCertProfile);
                                        
                                        try{                                        
                                            getRaAdminSession().addEndEntityProfile(getAdmin(),profileid,profilename,eprofile);
                                            getLogger().info("Added entity profile '"+profilename+"' to database.");
                                        }catch(EndEntityProfileExistsException eepee){  
                                        	getLogger().error("Error adding entity profile '"+profilename+"' to database.");
                                        }                                        
                                    } else {
                                    	
                                    	getCertificateStoreSession().importCertificateProfile(getAdmin(), decoder.readObject(), profilename, profileid);
                                    	getLogger().info("Certificate profile '" + profilename + "' was imported successfully.");
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
