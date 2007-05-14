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
 
/*
 * ApplyBean.java
 *
 * Created on den 3 nov 2002, 12:06
 */
package org.ejbca.core.model;


import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;

import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;




/**
 * A class used as an interface between Apply jsp pages and ejbca functions.
 *
 * @author Philip Vendil
 * @version $Id: ApplyBean.java,v 1.5 2007-05-14 10:58:31 anatom Exp $
 */
public class ApplyBean implements java.io.Serializable {

    // Public methods
    public void initialize(final HttpServletRequest request) throws NamingException {
        if (!initialized) {
            if (request.getAttribute("javax.servlet.request.X509Certificate") == null) {
                administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
            } else {
                administrator = new Admin(((X509Certificate[]) request.getAttribute(
                "javax.servlet.request.X509Certificate"))[0]);
            }

            final InitialContext jndicontext = new InitialContext();
            Object obj1 = jndicontext.lookup(IUserAdminSessionHome.JNDI_NAME);
            useradminhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    IUserAdminSessionHome.class);
            obj1 = jndicontext.lookup(ICertificateStoreSessionHome.JNDI_NAME);
            certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    ICertificateStoreSessionHome.class);
            initialized = true;
        }
    }

    /**
     * Method that returns a users tokentype defined in SecConst, if 0 is returned user couldn't be
     * found i database.
     *
     * @param username the user whose tokentype should be returned
     *
     * @return tokentype as defined in SecConst
     * @throws CreateException 
     * @throws RemoteException 
     * @throws AuthorizationDeniedException 
     *
     * @see org.ejbca.core.model.SecConst
     */
    public int getTokenType(final String username) throws RemoteException, CreateException, AuthorizationDeniedException {
        int returnval = 0;
        final IUserAdminSessionRemote useradminsession = useradminhome.create();

		if(!username.equals(this.username) || this.useradmindata == null){        
		  try {
			this.useradmindata = useradminsession.findUser(administrator, username);
		  } catch (FinderException fe) {
			  // empty, this is a quite normal case
		  }
		}
		
        if (useradmindata != null) {
            returnval = useradmindata.getTokenType();
        }
		this.username = username;
		
        return returnval;
    }

	/**
	 * Method that returns a users tokentype defined in SecConst, if 0 is returned user couldn't be
	 * found i database.
	 *
	 * @param username the user whose tokentype should be returned
	 *
	 * @return caid of user.
	 * @throws CreateException 
	 * @throws RemoteException 
	 * @throws AuthorizationDeniedException 
	 *
	 * @see org.ejbca.core.model.SecConst
	 */
	public int getCAId(final String username) throws RemoteException, CreateException, AuthorizationDeniedException {
		int returnval = 0;		
		final IUserAdminSessionRemote useradminsession = useradminhome.create();

		if(!username.equals(this.username) || this.useradmindata == null){        
		  try {
			this.useradmindata = useradminsession.findUser(administrator, username);
		  } catch (FinderException fe) {
			  // Not found, a quite normal case
		  }
		}
		
		if (useradmindata != null) {
			returnval = useradmindata.getCAId();
		}
		this.username = username;
		
		return returnval;
	}


    /**
     * Method that returns a bitlengths available for the user. Returns null if user couldn't be
     * found in database.
     *
     * @param username user whose bit lengts are requested.
     *
     * @return array of available bit lengths
     * @throws CreateException 
     * @throws RemoteException 
     * @throws AuthorizationDeniedException 
     */
    public int[] availableBitLengths(final String username) throws RemoteException, CreateException, AuthorizationDeniedException {
        int[] returnval = null;        
        final IUserAdminSessionRemote useradminsession = useradminhome.create();

        if(!username.equals(this.username) || this.useradmindata == null){        
          try {
            this.useradmindata = useradminsession.findUser(administrator, username);
          } catch (FinderException fe) {
        	  // Not found, quite normal 
          }
        }  

        if (useradmindata != null) {
            final ICertificateStoreSessionRemote certstoresession = certificatesessionhome.create();
            final int certprofile = useradmindata.getCertificateProfileId();

            if (certprofile != SecConst.PROFILE_NO_PROFILE) {
                final CertificateProfile prof = certstoresession.getCertificateProfile(administrator, certprofile);
                returnval = prof.getAvailableBitLengths();
            }
        }
        this.username = username;

        return returnval;
    }

    // Private methods
    // Private fields
    private transient IUserAdminSessionHome useradminhome;
    private transient ICertificateStoreSessionHome certificatesessionhome;
    private transient boolean initialized;
    private transient Admin administrator;
    private transient String username = "";
    private transient UserDataVO useradmindata = null;
}
