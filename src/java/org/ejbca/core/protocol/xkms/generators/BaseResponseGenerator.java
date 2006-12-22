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

package org.ejbca.core.protocol.xkms.generators;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.log.Admin;

/**
 * 
 * The most basic response generator that manages connections
 * with EJBCA session beans
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: BaseResponseGenerator.java,v 1.1 2006-12-22 09:21:39 herrvendil Exp $
 */

public abstract class BaseResponseGenerator {
	
	private static Logger log = Logger.getLogger(BaseResponseGenerator.class);
	
	protected Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
	
	public BaseResponseGenerator(){
		
	}

	
	private ICAAdminSessionLocal caadminsession = null;
	protected ICAAdminSessionLocal getCAAdminSession() throws ClassCastException, CreateException, NamingException{ 		
	    if(caadminsession == null){	  
	    	Context context = new InitialContext();	    	
	    	caadminsession = ((ICAAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
	    	"CAAdminSessionLocal"), ICAAdminSessionLocalHome.class)).create();   
	    }
	    return caadminsession;
	}
	
	private IRaAdminSessionLocal raadminsession = null;
	protected IRaAdminSessionLocal getRAAdminSession() throws ClassCastException, CreateException, NamingException{
		if(raadminsession == null){
		  Context context = new InitialContext();
	      raadminsession = ((IRaAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
	      "RaAdminSessionLocal"), IRaAdminSessionLocalHome.class)).create();    	           	           	        
		}
		return raadminsession;
	}
	
	private ICertificateStoreSessionLocal certificatestoresession = null;
	protected ICertificateStoreSessionLocal getCertStoreSession() throws ClassCastException, CreateException, NamingException{
		if(certificatestoresession == null){
			Context context = new InitialContext();
			certificatestoresession = ((ICertificateStoreSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
			"CertificateStoreSessionLocal"), ICertificateStoreSessionLocalHome.class)).create();    	           	           	        
		}
		return certificatestoresession;
	}
	
	private ISignSessionLocal signsession = null;
	protected ISignSessionLocal getSignSession() throws ClassCastException, CreateException, NamingException{
		if(signsession == null){
			Context context = new InitialContext();
			signsession = ((ISignSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
			"SignSessionLocal"), ISignSessionLocalHome.class)).create();    	           	           	        
		}
		return signsession;
	}
	
	private IUserAdminSessionLocal usersession = null;
	protected IUserAdminSessionLocal getUserAdminSession() {
		try{
			if(usersession == null){
				Context context = new InitialContext();
				usersession = ((IUserAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"UserAdminSessionLocal"), IUserAdminSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing User Admin Session Bean",e);
			throw new EJBException(e);
		}
		return usersession;
	}
	
	
	private IAuthorizationSessionLocal authsession = null;
	protected IAuthorizationSessionLocal getAuthorizationSession() {
		try{
			if(authsession == null){
				Context context = new InitialContext();
				authsession = ((IAuthorizationSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"AuthorizationSessionLocal"), IAuthorizationSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing Authorization Session Bean",e);
			throw new EJBException(e);
		}
		return authsession;
	}
	
}
