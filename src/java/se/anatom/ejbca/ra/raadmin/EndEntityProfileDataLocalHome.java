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
 
package se.anatom.ejbca.ra.raadmin;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;


/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocalHome.java,v 1.4 2004-04-16 07:38:41 anatom Exp $
 */
public interface EndEntityProfileDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     * @param profile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public EndEntityProfileDataLocal create(Integer id, String profilename, EndEntityProfile profile)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public EndEntityProfileDataLocal findByPrimaryKey(Integer id)
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
    public EndEntityProfileDataLocal findByProfileName(String name)
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
