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


import java.security.cert.X509Certificate;

import javax.ejb.FinderException;
import javax.naming.InitialContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;




/**
 * A class used as an interface between Apply jsp pages and ejbca functions.
 *
 * @author Philip Vendil
 * @version $Id: ApplyBean.java,v 1.8 2007-07-16 12:47:00 anatom Exp $
 */
public class ApplyBean implements java.io.Serializable {
    /**
	 * Version number for serialization
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Logging tool
	 */
	private static final Logger log = Logger.getLogger(ApplyBean.class);
	
	/**
     * Creates a new instance of CaInterfaceBean
     */
    public ApplyBean() {
    }

    // Public methods
    public void initialize(HttpServletRequest request)
        throws Exception {
        if (!initialized) {
            if (request.getAttribute("javax.servlet.request.X509Certificate") != null) {
                administrator = new Admin(((X509Certificate[]) request.getAttribute(
                            "javax.servlet.request.X509Certificate"))[0]);
            } else {
                administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
            }

            InitialContext jndicontext = new InitialContext();
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
     *
     * @see org.ejbca.core.model.SecConst
     */
    public int getTokenType(String username) throws Exception {
        int returnval = 0;
        IUserAdminSessionRemote useradminsession = useradminhome.create();

		if(!username.equals(this.username) || this.useradmindata == null){        
		  try {
			this.useradmindata = useradminsession.findUser(administrator, username);
		  } catch (FinderException fe) {
		  }
		}
		
        if (useradmindata != null) {
            returnval = useradmindata.getTokenType();
        }
		this.username = username;
		
		log.info("<getTokenType(" + username + ") --> " + returnval);
        return returnval;
    }

	/**
	 * Method that returns a users tokentype defined in SecConst, if 0 is returned user couldn't be
	 * found i database.
	 *
	 * @param username the user whose tokentype should be returned
	 *
	 * @return caid of user.
	 *
	 * @see org.ejbca.core.model.SecConst
	 */
	public int getCAId(String username) throws Exception {
		int returnval = 0;		
		IUserAdminSessionRemote useradminsession = useradminhome.create();

		if(!username.equals(this.username) || this.useradmindata == null){        
		  try {
			this.useradmindata = useradminsession.findUser(administrator, username);
		  } catch (FinderException fe) {
		  }
		}
		
		if (useradmindata != null) {
			returnval = useradmindata.getCAId();
		}
		this.username = username;
		
		log.info("<getCAId(" + username + ") --> " + returnval);
		return returnval;
	}


    /**
     * Method that returns a bitlengths available for the user. Returns null if user couldn't be
     * found in database.
     *
     * @param username user whose bit lengts are requested.
     *
     * @return array of available bit lengths
     */
    public int[] availableBitLengths(String username) throws Exception {
        int[] returnval = null;        
        IUserAdminSessionRemote useradminsession = useradminhome.create();

        if(!username.equals(this.username) || this.useradmindata == null){        
          try {
            this.useradmindata = useradminsession.findUser(administrator, username);
          } catch (FinderException fe) {
          }
        }  

        if (useradmindata != null) {
            ICertificateStoreSessionRemote certstoresession = certificatesessionhome.create();
            int certprofile = useradmindata.getCertificateProfileId();

            if (certprofile != SecConst.PROFILE_NO_PROFILE) {
                CertificateProfile p = certstoresession.getCertificateProfile(administrator, certprofile);
                returnval = p.getAvailableBitLengths();
            }
        }
        this.username = username;

		log.info("<availableBitLengths(" + username + ") --> " + returnval);
        return returnval;
    }

    // Private methods
    // Private fields
    private IUserAdminSessionHome useradminhome;
    private ICertificateStoreSessionHome certificatesessionhome;
    private boolean initialized;
    private Admin administrator;
    private String username = "";
    private UserDataVO useradmindata = null;
    
    //--------------------------------------------------------------
    // Convenience methods used from JSTL.
    // In JSTL, there is no practical way of calling regular functions,
    // but accessing "properties" of objects (get-methods without arguments)
    // is easy. Since most methods in ApplyBean take a "username" argument,
    // we give the JSP page a way to set the username beforehand and then
    // access the other methods like properties.
    
    private String defaultUsername = "";
    
    /**
     * Sets the default user name. Some methods in this class come in two versions,
     * one that takes a String username and one without arguments. The version without
     * argument uses the default user name set by this method. 
     * 
     * @param newUsername The new default user name
     */
    public void setDefaultUsername(String newUsername) {
    	defaultUsername = newUsername;
    }

    /**
     * Returns the token type for the default user.
     * @see #setDefaultUsername(String) 
     * @see #getTokenType(String)
     * @return the token type for the default user.
     * @throws Exception if an error occurs
     */
    public int getTokenType() throws Exception {
    	return getTokenType(defaultUsername);
    }

    /**
     * Returns the CA identity for the default user.
     * @see #setDefaultUsername(String) 
     * @see #getCAId(String)
     * @return the CA Id for the default user.
     * @throws Exception if an error occurs
     */
	public int getCAId() throws Exception {
    	return getCAId(defaultUsername);
    }

    /**
     * Returns the encryption key lengths available to the default user.
     * @see #setDefaultUsername(String) 
     * @see #availableBitLengths(String)
     * @return the bit lengths available to the default user.
     * @throws Exception if an error occurs
     */
	public int[] getAvailableBitLengths() throws Exception {
		return availableBitLengths(defaultUsername);
	}
	

    /**
     * Returns the default encryption key lengths.
     * @see #availableBitLengths(String)
     * @return the default bit lengths available.
     * @throws Exception if an error occurs
     */
	public int[] getDefaultBitLengths() throws Exception {
		return SecConst.DEFAULT_KEY_LENGTHS;
	}
}
