package se.anatom.ejbca.admin;

import java.beans.XMLEncoder;
import java.io.FileOutputStream;

import javax.naming.*;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;


/**
 * Export profiles from the databse to XML-files.
 *
 * @version $Id: CaExportProfilesCommand.java,v 1.2 2003-08-20 09:50:11 anatom Exp $
 */
public class CaExportProfilesCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaExportProfilesCommand
     *
     * @param args command line arguments
     */
    public CaExportProfilesCommand(String[] args) {
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

            String[] certprofnames = (String[]) certificatesession.getCertificateProfileNames(administrator)
                                                                  .toArray((Object[]) new String[0]);
            String[] endentityprofilenames = (String[]) raadminsession.getEndEntityProfileNames(administrator)
                                                                      .toArray((Object[]) new String[0]);

            if (args.length < 2) {
                System.out.println(
                    "Usage: CA exportprofiles <outpath>");
                System.out.print("\n");
                return;
            }

            String outpath = args[1];
            boolean error = false;

            System.out.println("Exporting certificate profiles: ");
            for (int i = 0; i < (certprofnames.length); i++) {
                String profilename = certprofnames[i];
                int profileid = certificatesession.getCertificateProfileId(administrator, profilename);
                if (profileid == SecConst.PROFILE_NO_PROFILE) { // Certificate profile not found i database.
                    System.out.println("Error : Couldn't find certificate profile '"+profilename+"' in database.");
                } else {
                    CertificateProfile profile = certificatesession.getCertificateProfile(administrator,profileid);
                    String outfile = outpath+"/certprofile_"+profilename+"-"+profileid+".xml";
                    System.out.println(outfile+".");
                    XMLEncoder encoder = new XMLEncoder(new  FileOutputStream(outfile));
                    encoder.writeObject(profile);
                    encoder.close();
                }
            }

            System.out.println("Exporting end entity profiles: ");
            for (int i = 0; i < (endentityprofilenames.length); i++) {
                String profilename = endentityprofilenames[i];
                int profileid = raadminsession.getEndEntityProfileId(administrator, profilename);
                if (profileid == SecConst.PROFILE_NO_PROFILE) { // Entity profile not found i database.
                    System.out.println("Error : Couldn't find entity profile '"+profilename+"' in database.");
                } else {
                    EndEntityProfile profile = raadminsession.getEndEntityProfile(administrator, profileid);
                    String outfile = outpath+"/entityprofile_"+profilename+"-"+profileid+".xml";
                    System.out.println(outfile+".");
                    XMLEncoder encoder = new XMLEncoder(new  FileOutputStream(outfile));
                    encoder.writeObject(profile);
                    encoder.close();
                }
            }

        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
