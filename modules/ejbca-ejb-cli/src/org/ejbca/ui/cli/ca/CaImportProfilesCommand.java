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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
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
                                        	if ( (currentCAInt.intValue() != SecConst.ALLCAS) && (getCAAdminSession().getCAInfo(getAdmin(), currentCAInt) == null) ) {
                                        		getLogger().warn("CA with id " + currentCA + " was not found and will not be used in end entity profile '" + profilename + "'.");
                                                if (defaultCA.equals(currentCA)) {
                                                	defaultCA = "";
                                                }
                                        	} else {
                                        		availableCAs += (availableCAs.equals("") ? "" : ";" ) + currentCA;
                                        	}
                                        }
                                        if (availableCAs.equals("")) {
                                        	if (caid == null) {
                                        		getLogger().error("No CAs left in end entity profile '" + profilename + "' and no CA specified on command line. Using ALLCAs.");
                                        		availableCAs = Integer.toString(SecConst.ALLCAS);
                                        	} else {
                                        		availableCAs = Integer.toString(caid);
                                        		getLogger().warn("No CAs left in end entity profile '" + profilename + "'. Using CA supplied on command line with id '"+caid+"'.");
                                        	}
                                        }
                                        if (defaultCA.equals("")) {
                                        	defaultCA = availableCAs.split(";")[0];	// Use first available
                                        	getLogger().warn("Changing default CA in end entity profile '" + profilename + "' to "+defaultCA+".");
                                        }
                                    	//getLogger().debug("New - AVAILCAS " + availableCAs + " DEFAULTCA "+defaultCA);
                                        eprofile.setValue(EndEntityProfile.AVAILCAS, 0, availableCAs);
                                        eprofile.setValue(EndEntityProfile.DEFAULTCA, 0, defaultCA);
                                        try{                                        
                                            getRaAdminSession().addEndEntityProfile(getAdmin(),profileid,profilename,eprofile);
                                            getLogger().info("Added entity profile '"+profilename+"' to database.");
                                        }catch(EndEntityProfileExistsException eepee){  
                                        	getLogger().error("Error adding entity profile '"+profilename+"' to database.");
                                        }                                        
                                    } else {
                                        cprofile = new CertificateProfile();
                                        cprofile.loadData(decoder.readObject());
                                        // Make sure CAs in profile exist
                                        Collection<Integer> cas = cprofile.getAvailableCAs();
                                        ArrayList<Integer> casToRemove = new ArrayList<Integer>();
                                        for (Integer currentCA : cas) {
                                        	if (currentCA != CertificateProfile.ANYCA && getCAAdminSession().getCAInfo(getAdmin(), currentCA) == null) {
                                        		casToRemove.add(currentCA);
                                        	}
                                        }
                                        for (Integer toRemove : casToRemove) {
                                        	getLogger().warn("Warning: CA with id " + toRemove + " was not found and will not be used in certificate profile '" + profilename + "'.");
                                        	cas.remove(toRemove);
                                        }
                                        if (cas.size() == 0) {
                                        	if (caid == null) {
                                        		getLogger().error("Error: No CAs left in certificate profile '" + profilename + "' and no CA specified on command line. Using ANYCA.");
                                        		cas.add(Integer.valueOf(CertificateProfile.ANYCA));
                                        	} else {
                                        		getLogger().warn("Warning: No CAs left in certificate profile '" + profilename + "'. Using CA supplied on command line with id '"+caid+"'.");
                                            	cas.add(caid);
                                        	}
                                        }
                                        cprofile.setAvailableCAs(cas);
                                        // Remove and warn about unknown publishers
                                        Collection<Integer> publishers = cprofile.getPublisherList();
                                        ArrayList<Integer> allToRemove = new ArrayList<Integer>();
                                        for (Integer publisher : publishers) {
                                        	BasePublisher pub = null;
                                        	try {
                                        		pub = getPublisherSession().getPublisher(getAdmin(), publisher);
                                        	} catch (Exception e) {
                                        		String msg = e.getMessage();
                                        		if (e.getCause() != null) {
                                        			msg += ": "+e.getCause().getMessage();
                                        		}
                                        		getLogger().warn("Warning: There was an error loading publisher with id " + publisher + ". Use debug logging to see stack trace: "+e.getMessage());
                                        		getLogger().debug("Full stack trace: ", e);
                                        	}
                                        	if (pub == null) {
                                        		allToRemove.add(publisher);
                                        	}
                                        }
                                        for (Integer toRemove : allToRemove) {
                                        	getLogger().warn("Warning: Publisher with id " + toRemove + " was not found and will not be used in certificate profile '" + profilename + "'.");
                                        	publishers.remove(toRemove);
                                        }
                                        cprofile.setPublisherList(publishers);
                                        // Add profile
                                        try{
                                            getCertificateStoreSession().addCertificateProfile(getAdmin(),profileid,profilename,cprofile);
                                            certificateProfileIdMapping.put(profileid, getCertificateStoreSession().getCertificateProfileId(getAdmin(),profilename));
                                            getLogger().info("Added certificate profile '"+profilename+"' to database.");
                                        }catch(CertificateProfileExistsException cpee){
                                        	getLogger().error("Error adding certificate profile '"+profilename+"' to database.");
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
