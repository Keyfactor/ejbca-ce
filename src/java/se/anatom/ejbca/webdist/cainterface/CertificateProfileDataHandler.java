package se.anatom.ejbca.webdist.cainterface;

import java.io.Serializable;
import java.rmi.RemoteException;
import java.util.TreeMap;

import javax.ejb.FinderException;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;


/**
 * A class handling the certificate type data. It saves and retrieves them currently from a
 * database.
 *
 * @author TomSelleck
 */
public class CertificateProfileDataHandler implements Serializable {
    public static final int FIXED_CERTIFICATEPROFILE_BOUNDRY = SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY;

    /**
     * Creates a new instance of CertificateProfileDataHandler
     *
     * @param certificatesession DOCUMENT ME!
     * @param admin DOCUMENT ME!
     */
    public CertificateProfileDataHandler(ICertificateStoreSessionRemote certificatesession,
        Admin admin) throws RemoteException, FinderException {
        certificatestoresession = certificatesession;
        this.admin = admin;
    }

    /**
     * Method to add a certificateprofile. Throws CertificateProfileExitsException if
     * certificateprofile already exists
     *
     * @param name DOCUMENT ME!
     * @param certificateprofile DOCUMENT ME!
     */
    public void addCertificateProfile(String name, CertificateProfile certificateprofile)
        throws CertificateProfileExistsException, RemoteException {
        if (!certificatestoresession.addCertificateProfile(admin, name, certificateprofile)) {
            throw new CertificateProfileExistsException(name);
        }
    }

    /**
     * Method to change a  certificateprofile. Throws CertificateProfileDoesntExitsException if
     * certificateprofile cannot be found
     *
     * @param name DOCUMENT ME!
     * @param certificateprofile DOCUMENT ME!
     */
    public void changeCertificateProfile(String name, CertificateProfile certificateprofile)
        throws CertificateProfileDoesntExistsException, RemoteException {
        if (!certificatestoresession.changeCertificateProfile(admin, name, certificateprofile)) {
            throw new CertificateProfileDoesntExistsException(name);
        }
    }

    /**
     * Method to remove a certificateprofile.
     *
     * @param name DOCUMENT ME!
     */
    public void removeCertificateProfile(String name) throws RemoteException {
        certificatestoresession.removeCertificateProfile(admin, name);
    }

    /**
     * Metod to rename a certificateprofile
     *
     * @param oldname DOCUMENT ME!
     * @param newname DOCUMENT ME!
     */
    public void renameCertificateProfile(String oldname, String newname)
        throws CertificateProfileExistsException, RemoteException {
        if (!certificatestoresession.renameCertificateProfile(admin, oldname, newname)) {
            throw new CertificateProfileExistsException(newname);
        }
    }

    /**
     * Method to get a reference to a certificateprofile.
     *
     * @param name DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile getCertificateProfile(String name)
        throws RemoteException {
        return certificatestoresession.getCertificateProfile(admin, name);
    }

    /**
     * Returns the number of certificateprofiles i database.
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfCertificateProfiles() throws RemoteException {
        return certificatestoresession.getNumberOfCertificateProfiles(admin);
    }

    /**
     * Returns an array containing all the certificateprofiles names.
     *
     * @return DOCUMENT ME!
     */
    public String[] getCertificateProfileNames() throws RemoteException {
        String[] dummy = {  };
        TreeMap result = certificatestoresession.getCertificateProfiles(admin);

        return (String[]) result.keySet().toArray(dummy);
    }

    /**
     * Returns an array containing all the certificatetypes.
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile[] getCertificateProfiles()
        throws RemoteException {
        CertificateProfile[] dummy = {  };
        TreeMap result = certificatestoresession.getCertificateProfiles(admin);

        return (CertificateProfile[]) result.values().toArray(dummy);
    }

    /**
     * DOCUMENT ME!
     *
     * @param originalname DOCUMENT ME!
     * @param newname DOCUMENT ME!
     *
     * @throws CertificateProfileExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void cloneCertificateProfile(String originalname, String newname)
        throws CertificateProfileExistsException, RemoteException {
        // Check if original certificatetype already exists.
        if (!certificatestoresession.cloneCertificateProfile(admin, originalname, newname)) {
            throw new CertificateProfileExistsException(newname);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getCertificateProfileId(String certificateprofilename)
        throws RemoteException {
        return certificatestoresession.getCertificateProfileId(admin, certificateprofilename);
    }

    private ICertificateStoreSessionRemote certificatestoresession;
    private Admin admin;
}
