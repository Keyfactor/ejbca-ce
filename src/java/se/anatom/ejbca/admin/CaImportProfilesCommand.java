package se.anatom.ejbca.admin;

import java.beans.XMLDecoder;
import java.io.File;
import java.io.FileInputStream;

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
 * @version $Id: CaImportProfilesCommand.java,v 1.5 2003-10-03 14:34:20 herrvendil Exp $
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

            InitialContext jndicontext = new InitialContext();

            Object obj1 = jndicontext.lookup("CertificateStoreSession");
            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create();

            obj1 = jndicontext.lookup("RaAdminSession");

            IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "RaAdminSession"), IRaAdminSessionHome.class);
            IRaAdminSessionRemote raadminsession = raadminsessionhome.create();



            if (args.length < 2) {
                System.out.println("Usage: CA importprofiles <inpath>");
                System.out.print("\n");
                return;
            }

            String inpath = args[1];

            System.out.println("Importing certificate and entity profiles: ");
            File inFile = new File(inpath);
            // List all filenames in the given directory, we will try to import them all
            File[] infiles = inFile.listFiles();
            for (int i = 0; i < infiles.length; i++) {
                System.out.println("Filename:"+infiles[i].getName());
                if ( infiles[i].isFile() && ((infiles[i].getName().indexOf("certprofile_") > -1) || (infiles[i].getName().indexOf("entityprofile_") > -1)) ) {
                    boolean entityprofile = false;
                    if (infiles[i].getName().indexOf("entityprofile_") > -1) {
                        entityprofile=true;
                    }
                    int index1 = infiles[i].getName().indexOf("_");
                    int index2 = infiles[i].getName().lastIndexOf("-");
                    int index3 = infiles[i].getName().lastIndexOf(".xml");
                    if (index1 < 0 || index2 < 0 || index3 < 0) {
                        System.out.println("Error: Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
                    } else {
                        String profilename = infiles[i].getName().substring(index1+1,index2);
                        //System.out.println("Name:"+profilename);
                        //System.out.println("Id:"+infiles[i].getName().substring(index2+1,index3));
                        int profileid = Integer.parseInt(infiles[i].getName().substring(index2+1,index3));
                        // We don't add the fixed profiles, EJBCA handles those automagically
                        if ( (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_ENDUSER) || 
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_SUBCA) ||
                            (!entityprofile && profileid == SecConst.CERTPROFILE_FIXED_ROOTCA) ) { 
                            System.out.println("Not adding fixed certificate profile '"+profilename+"'.");
                        } else {
                            if (entityprofile && profileid == SecConst.EMPTY_ENDENTITYPROFILE) {
                                System.out.println("Not adding fixed entity profile '"+profilename+"'.");
                            } else {
                                // Check if the profiles already exist, cause we donät want to add them if they do
                                boolean error = false;
                                if (entityprofile) {
                                    if (raadminsession.getEndEntityProfileId(administrator, profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        System.out.println("Error: Entity profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    }
                                    if (raadminsession.getEndEntityProfile(administrator, profileid) != null) {
                                        System.out.println("Error: Entity profileid '"+profileid+"' already exist in database.");
                                        error = true;
                                    }
                                } else {
                                    if (certificatesession.getCertificateProfileId(administrator,profilename) != SecConst.PROFILE_NO_PROFILE) {
                                        System.out.println("Error: Certificate profile '"+profilename+"' already exist in database.");
                                        error = true;
                                    }
                                    if (certificatesession.getCertificateProfile(administrator,profileid) != null) {
                                        System.out.println("Error: Certificate profile id '"+profileid+"' already exist in database.");
                                        error = true;
                                    }
                                }
                                if (!error) {
                                    CertificateProfile cprofile = null;
                                    EndEntityProfile eprofile = null;
                                    FileInputStream is = new FileInputStream(infiles[i]);
                                    XMLDecoder decoder = new XMLDecoder( is );
                                    if (entityprofile) {
                                        eprofile = (EndEntityProfile)decoder.readObject();
                                        try{                                        
                                           raadminsession.addEndEntityProfile(administrator,profileid,profilename,eprofile);
										   System.out.println("Added entity profile '"+profilename+"' to database.");
                                        }catch(EndEntityProfileExistsException eepee){  
										  System.out.println("Error: Error adding entity profile '"+profilename+"' to database.");
                                        }                                        
                                    } else {
                                        cprofile = (CertificateProfile)decoder.readObject();
                                        try{                                        
                                          certificatesession.addCertificateProfile(administrator,profileid,profilename,cprofile);
										  System.out.println("Added certificate profile '"+profilename+"' to database.");
                                        }catch(CertificateProfileExistsException cpee){
											System.out.println("Error: Error adding certificate profile '"+profilename+"' to database.");
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
