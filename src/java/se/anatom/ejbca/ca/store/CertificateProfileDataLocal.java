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
