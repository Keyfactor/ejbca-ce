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

package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;
import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocalHome.java,v 1.9 2004-06-10 15:05:45 sbailliez Exp $
 */
public interface KeyRecoveryDataLocalHome extends javax.ejb.EJBLocalHome {

    public static final String COMP_NAME = "java:comp/env/ejb/KeyRecoveryData";
    public static final String JNDI_NAME = "KeyRecoveryData";


    public KeyRecoveryDataLocal create(BigInteger certificatesn, String issuerdn, String username,
                                       byte[] keydata) throws CreateException;


    public KeyRecoveryDataLocal findByPrimaryKey(KeyRecoveryDataPK pk)
            throws FinderException;

    public Collection findByUsername(String username) throws FinderException;

    public Collection findByUserMark(String username) throws FinderException;

}
