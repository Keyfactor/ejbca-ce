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
 * @version $Id: KeyRecoveryDataLocalHome.java,v 1.8 2004-06-08 18:06:05 sbailliez Exp $
 */
public interface KeyRecoveryDataLocalHome extends javax.ejb.EJBLocalHome {

    public static final String COMP_NAME = "java:comp/env/ejb/KeyRecoveryDataLocal";
    public static final String JNDI_NAME = "KeyRecoveryData";


    public KeyRecoveryDataLocal create(BigInteger certificatesn, String issuerdn, String username,
                                       byte[] keydata) throws CreateException;


    public KeyRecoveryDataLocal findByPrimaryKey(KeyRecoveryDataPK pk)
            throws FinderException;

    public Collection findByUsername(String username) throws FinderException;

    public Collection findByUserMark(String username) throws FinderException;

}
