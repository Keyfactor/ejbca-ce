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

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.ca.store.certificateprofiles.*;


/**
 * For docs, see CertificateProfileDataBean
 *
 * @version $Id: CertificateProfileDataLocalHome.java,v 1.3 2002/07/22 10:38:48 herrvendil Exp $
 */
public interface CertificateProfileDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     * @param certificateprofile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public CertificateProfileDataLocal create(Integer id, String certificateprofilename,
        CertificateProfile certificateprofile) throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public CertificateProfileDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public CertificateProfileDataLocal findByCertificateProfileName(String name)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findAll() throws FinderException;
}
