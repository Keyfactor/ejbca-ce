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
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;

/**
 * 
 * The most basic response generator that manages connections
 * with EJBCA session beans
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */

public abstract class BaseResponseGenerator {
	
	private static Logger log = Logger.getLogger(BaseResponseGenerator.class);
	
	private static final InternalResources intres = InternalResources.getInstance();
	
	protected Admin raAdmin = null;
	protected Admin pubAdmin = null;
	
	protected String remoteIP = null;
	
	public BaseResponseGenerator(String remoteIP){
		  this.remoteIP = remoteIP;
		  raAdmin = new Admin(Admin.TYPE_RA_USER,remoteIP);
		  pubAdmin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteIP);
	}

	
	private ICAAdminSessionLocal caadminsession = null;
	protected ICAAdminSessionLocal getCAAdminSession() throws ClassCastException, CreateException, NamingException{ 		
	    if(caadminsession == null){	  
	    	Context context = new InitialContext();	    	
	    	caadminsession = ((ICAAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
	    			ICAAdminSessionLocalHome.COMP_NAME), ICAAdminSessionLocalHome.class)).create();   
	    }
	    return caadminsession;
	}
	
	private IRaAdminSessionLocal raadminsession = null;
	protected IRaAdminSessionLocal getRAAdminSession() throws ClassCastException, CreateException, NamingException{
		if(raadminsession == null){
		  Context context = new InitialContext();
	      raadminsession = ((IRaAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
	    		  IRaAdminSessionLocalHome.COMP_NAME), IRaAdminSessionLocalHome.class)).create();    	           	           	        
		}
		return raadminsession;
	}
	
	private ICertificateStoreSessionLocal certificatestoresession = null;
	protected ICertificateStoreSessionLocal getCertStoreSession() throws ClassCastException, CreateException, NamingException{
		if(certificatestoresession == null){
			Context context = new InitialContext();
			certificatestoresession = ((ICertificateStoreSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
					ICertificateStoreSessionLocalHome.COMP_NAME), ICertificateStoreSessionLocalHome.class)).create();    	           	           	        
		}
		return certificatestoresession;
	}
	
	private ICreateCRLSessionLocal createCRLSession = null;
	protected ICreateCRLSessionLocal getCreateCRLSession() throws ClassCastException, CreateException, NamingException{
		if(createCRLSession == null){
			Context context = new InitialContext();
			createCRLSession = ((ICreateCRLSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
					ICreateCRLSessionLocalHome.COMP_NAME), ICreateCRLSessionLocalHome.class)).create();    	           	           	        
		}
		return createCRLSession;
	}
	
	private ISignSessionLocal signsession = null;
	protected ISignSessionLocal getSignSession() throws ClassCastException, CreateException, NamingException{
		if(signsession == null){
			Context context = new InitialContext();
			signsession = ((ISignSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
					ISignSessionLocalHome.COMP_NAME), ISignSessionLocalHome.class)).create();    	           	           	        
		}
		return signsession;
	}
	
	private IUserAdminSessionLocal usersession = null;
	protected IUserAdminSessionLocal getUserAdminSession() {
		try{
			if(usersession == null){
				Context context = new InitialContext();
				usersession = ((IUserAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
						IUserAdminSessionLocalHome.COMP_NAME), IUserAdminSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error(intres.getLocalizedMessage("xkms.errorinitadminsession"));			
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
						IAuthorizationSessionLocalHome.COMP_NAME), IAuthorizationSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error(intres.getLocalizedMessage("xkms.errorinitauthsession"));			
			throw new EJBException(e);
		}
		return authsession;
	}
	
	private IKeyRecoverySessionLocal keyrecoverysession = null;
	protected IKeyRecoverySessionLocal getKeyRecoverySession() {
		try{
			if(keyrecoverysession == null){
				Context context = new InitialContext();
				keyrecoverysession = ((IKeyRecoverySessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
						IKeyRecoverySessionLocalHome.COMP_NAME), IKeyRecoverySessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error(intres.getLocalizedMessage("xkms.errorinitkeyrecsession"));			
			throw new EJBException(e);
		}
		return keyrecoverysession;
	}
	
	private IAuthenticationSessionLocal authenticationSession = null;
	protected IAuthenticationSessionLocal getAuthenticationSession() {
		try{
			if(authenticationSession == null){
				Context context = new InitialContext();
				authenticationSession = ((IAuthenticationSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				IAuthenticationSessionLocalHome.COMP_NAME), IAuthenticationSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error(intres.getLocalizedMessage("xkms.errorinitauthentsession"));			
			throw new EJBException(e);
		}
		return authenticationSession;
	}

	
}
