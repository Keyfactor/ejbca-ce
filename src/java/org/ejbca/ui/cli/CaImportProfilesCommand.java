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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.util.FileTools;



/**
 * Export profiles from the databse to XML-files.
 *
 * @version $Id$
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
                getOutputStream().println("Usage: CA importprofiles <inpath> [<CAName>]");
                getOutputStream().print("\n");
                return;
            }
            String inpath = args[1];
            Integer caid = null;
            if (args.length > 2) {
            	CAInfo ca = getCAAdminSession().getCAInfo(administrator, args[2]);
            	if (ca != null) {
            		caid = ca.getCAId();
            	} else {
                    getOutputStream().println("CA '"+args[2]+"' does not exist.");
                    getOutputStream().print("\n");
                    return;
            	}
            }
            HashMap<Integer, Integer> certificateProfileIdMapping = new HashMap<Integer, Integer>();
            getOutputStream().println("Importing certificate and end entity profiles: ");
            File inFile = new File(inpath);
            if (!inFile.isDirectory()) {
                getOutputStream().println("Error: '"+inpath+"' is not a directory.");
                return;
            }
            // List all filenames in the given directory, we will try to import them all
            File[] infiles = inFile.listFiles();
            FileTools.sortByName(infiles);
            for (int i = 0; i < infiles.length; i++) {
                getOutputStream().println("Filename: "+infiles[i].getName());
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
                        if ( !entityprofile && SecConst.isFixedCertificateProfile(profileid) ) { 
                            getOutputStream().println("Not adding fixed certificate profile '"+profilename+"'.");
                        } else {
                            if (entityprofile && profileid == SecConst.EMPTY_ENDENTITYPROFILE) {
                                getOutputStream().println("Not adding fixed entity profile '"+profilename+"'.");
                            } else {
                                // Check if the profiles already exist, and change the name and id if already taken
                                boolean error = false;
                                if (entityprofile) {
                                    if (getRaAdminSession().getEndEntityProfileId(administrator, profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        getOutputStream().println("Error: Entity profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    } else if (getRaAdminSession().getEndEntityProfile(administrator, profileid) != null) {
                                        int newprofileid = getRaAdminSession().findFreeEndEntityProfileId();
                                        getOutputStream().println("Warning: Entity profileid '"+profileid+"' already exist in database. Using " + newprofileid + " instead.");
                                        profileid = newprofileid;
                                    }
                                } else {
                                    if (getCertificateStoreSession().getCertificateProfileId(administrator,profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        getOutputStream().println("Error: Certificate profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    } else if (getCertificateStoreSession().getCertificateProfile(administrator,profileid) != null) {
                                    	int newprofileid  = getCertificateStoreSession().findFreeCertificateProfileId();
                                        getOutputStream().println("Warning: Certificate profile id '"+profileid+"' already exist in database. Using " + newprofileid + " instead.");
                                        certificateProfileIdMapping.put(profileid, newprofileid);
                                        profileid = newprofileid;
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
                                        // Translate cert profile ids that have changed after import
                                        String availableCertProfiles = "";
                                        String defaultCertProfile = eprofile.getValue(EndEntityProfile.DEFAULTCERTPROFILE,0);
                                    	//getOutputStream().println("Debug: Org - AVAILCERTPROFILES " + eprofile.getValue(EndEntityProfile.AVAILCERTPROFILES,0) + " DEFAULTCERTPROFILE "+defaultCertProfile);
                                        for (String currentCertProfile : (Collection<String>) eprofile.getAvailableCertificateProfileIds()) {
                                        	Integer replacementCertProfileId = certificateProfileIdMapping.get(Integer.parseInt(currentCertProfile));
                                        	if ( replacementCertProfileId != null ) {
                                        		if (!replacementCertProfileId.toString().equals(currentCertProfile)) {
                                                    getOutputStream().println("Warning: Replacing cert profile with id "+currentCertProfile+" with " + replacementCertProfileId + ".");
                                        		}
                                        		availableCertProfiles += (availableCertProfiles.equals("") ? "" : ";" ) + replacementCertProfileId;
                                        		if (currentCertProfile.equals(defaultCertProfile)) {
                                        			defaultCertProfile = ""+replacementCertProfileId;
                                        		}
                                        	} else {
                                        		if (getCertificateStoreSession().getCertificateProfile(administrator, currentCertProfile) != null ||
                                        				SecConst.isFixedCertificateProfile(Integer.parseInt(currentCertProfile))) {
                                            		availableCertProfiles += (availableCertProfiles.equals("") ? "" : ";" ) + currentCertProfile;
                                       			} else {
                                                    getOutputStream().println("Warning: End Entity Profile '"+profilename+"' references certificate profile " + currentCertProfile + " that does not exist.");
                                            		if (currentCertProfile.equals(defaultCertProfile)) {
                                            			defaultCertProfile = "";
                                            		}
                                       			}
                                        	}
                                        }
                                        if (availableCertProfiles.equals("")) {
                                            getOutputStream().println("Warning: End Entity Profile only references certificate profile(s) that does not exist. Using ENDUSER profile.");
                                            availableCertProfiles = "1"; // At least make sure the default profile is available
                                        }
                                        if (defaultCertProfile.equals("")) {
                                        	defaultCertProfile = availableCertProfiles.split(";")[0];	// Use first available profile from list as default if original default was missing
                                        }
                                    	//getOutputStream().println("Debug: New - AVAILCERTPROFILES " + availableCertProfiles + " DEFAULTCERTPROFILE "+defaultCertProfile);
                                        eprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, availableCertProfiles);
                                        eprofile.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0, defaultCertProfile);
                                        // Remove any unknown CA and break if none is left
                                        String defaultCA = eprofile.getValue(EndEntityProfile.DEFAULTCA,0);
                                        String availableCAs = eprofile.getValue(EndEntityProfile.AVAILCAS,0);
                                    	//getOutputStream().println("Debug: Org - AVAILCAS " + availableCAs + " DEFAULTCA "+defaultCA);
                                        List<String> cas = Arrays.asList(availableCAs.split(";"));
                                        availableCAs = "";
                                        for ( String currentCA : cas ) {
                                        	Integer currentCAInt = Integer.parseInt(currentCA);
                                        	// The constant ALLCAS will not be searched for among available CAs
                                        	if ( (currentCAInt.intValue() != SecConst.ALLCAS) && (getCAAdminSession().getCAInfo(administrator, currentCAInt) == null) ) {
                                                getOutputStream().println("Warning: CA with id " + currentCA + " was not found and will not be used in end entity profile '" + profilename + "'.");
                                                if (defaultCA.equals(currentCA)) {
                                                	defaultCA = "";
                                                }
                                        	} else {
                                        		availableCAs += (availableCAs.equals("") ? "" : ";" ) + currentCA;
                                        	}
                                        }
                                        if (availableCAs.equals("")) {
                                        	if (caid == null) {
                                            	getOutputStream().println("Error: No CAs left in end entity profile '" + profilename + "' and no CA specified on command line. The profile was not imported.");
                                            	continue;
                                        	} else {
                                        		availableCAs = "" +caid;
                                            	getOutputStream().println("Warning: No CAs left in end entity profile '" + profilename + "'. Using CA supplied on command line with id '"+caid+"'.");
                                        	}
                                        }
                                        if (defaultCA.equals("")) {
                                        	defaultCA = availableCAs.split(";")[0];	// Use first available
                                        	getOutputStream().println("Warning: Changing default CA in end entity profile '" + profilename + "' to "+defaultCA+".");
                                        }
                                    	//getOutputStream().println("Debug: New - AVAILCAS " + availableCAs + " DEFAULTCA "+defaultCA);
                                        eprofile.setValue(EndEntityProfile.AVAILCAS, 0, availableCAs);
                                        eprofile.setValue(EndEntityProfile.DEFAULTCA, 0, defaultCA);
                                        try{                                        
                                            getRaAdminSession().addEndEntityProfile(administrator,profileid,profilename,eprofile);
                                            getOutputStream().println("Added entity profile '"+profilename+"' to database.");
                                        }catch(EndEntityProfileExistsException eepee){  
                                            getOutputStream().println("Error: Error adding entity profile '"+profilename+"' to database.");
                                        }                                        
                                    } else {
                                        cprofile = new CertificateProfile();
                                        cprofile.loadData(decoder.readObject());
                                        // Make sure CAs in profile exist
                                        Collection<Integer> cas = cprofile.getAvailableCAs();
                                        ArrayList<Integer> casToRemove = new ArrayList<Integer>();
                                        for (Integer currentCA : cas) {
                                        	if (currentCA != CertificateProfile.ANYCA && getCAAdminSession().getCAInfo(administrator, currentCA) == null) {
                                        		casToRemove.add(currentCA);
                                        	}
                                        }
                                        for (Integer toRemove : casToRemove) {
                                            getOutputStream().println("Warning: CA with id " + toRemove + " was not found and will not be used in certificate profile '" + profilename + "'.");
                                        	cas.remove(toRemove);
                                        }
                                        if (cas.size() == 0) {
                                        	if (caid == null) {
                                            	getOutputStream().println("Error: No CAs left in certificate profile '" + profilename + "' and no CA specified on command line. The profile was not imported.");
                                            	continue;
                                        	} else {
                                            	getOutputStream().println("Warning: No CAs left in certificate profile '" + profilename + "'. Using CA supplied on command line with id '"+caid+"'.");
                                            	cas.add(caid);
                                        	}
                                        }
                                        cprofile.setAvailableCAs(cas);
                                        // Remove and warn about unknown publishers
                                        Collection<Integer> publishers = cprofile.getPublisherList();
                                        ArrayList<Integer> allToRemove = new ArrayList<Integer>();
                                        for (Integer publisher : publishers) {
                                        	if (getPublisherSession().getPublisher(administrator, publisher) == null) {
                                        		allToRemove.add(publisher);
                                        	}
                                        }
                                        for (Integer toRemove : allToRemove) {
                                            getOutputStream().println("Warning: Publisher with id " + toRemove + " was not found and will not be used in certificate profile '" + profilename + "'.");
                                        	publishers.remove(toRemove);
                                        }
                                        cprofile.setPublisherList(publishers);
                                        // Add profile
                                        try{
                                            getCertificateStoreSession().addCertificateProfile(administrator,profileid,profilename,cprofile);
                                            certificateProfileIdMapping.put(profileid, getCertificateStoreSession().getCertificateProfileId(administrator,profilename));
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
