package se.anatom.ejbca.ca.store;

import se.anatom.ejbca.ca.store.certificateprofiles.*;


/**
 * For docs, see CertificateProfileDataBean
 *
 * @version $Id: CertificateProfileDataLocal.java,v 1.3 2002/07/22 10:38:48 tomselleck Exp $
 */
public interface CertificateProfileDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getCertificateProfileName();

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofilename DOCUMENT ME!
     */
    public void setCertificateProfileName(String certificateprofilename);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile getCertificateProfile();

    /**
     * DOCUMENT ME!
     *
     * @param certificateprofile DOCUMENT ME!
     */
    public void setCertificateProfile(CertificateProfile certificateprofile);
}
