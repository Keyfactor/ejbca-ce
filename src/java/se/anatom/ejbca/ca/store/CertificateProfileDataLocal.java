package se.anatom.ejbca.ca.store;
import java.rmi.RemoteException;

import se.anatom.ejbca.ca.store.certificateprofiles.*;

/**
 * For docs, see CertificateProfileDataBean
 *
 * @version $Id: CertificateProfileDataLocal.java,v 1.3 2002/07/22 10:38:48 tomselleck Exp $
 **/

public interface CertificateProfileDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public String getCertificateProfileName();

    public void setCertificateProfileName(String certificateprofilename);

    public CertificateProfile getCertificateProfile();

    public void setCertificateProfile(CertificateProfile certificateprofile);
}

