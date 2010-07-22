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
package org.ejbca.core.model.approval;

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;



/**
 * Helper class containing static methods for RMI lookups
 *  
 * 
 * 
 * @author Philip Vendil
 * @version $Id$
 */

public class ApprovalRequestHelper { 
	

	
	// Help Methods for approval requests
	public static String getCAName(Admin admin,int caid){
		String caname;
			    
		try {
			ServiceLocator locator = ServiceLocator.getInstance();
			ICAAdminSessionLocalHome home = (ICAAdminSessionLocalHome) locator.getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
			ICAAdminSessionLocal session = home.create();
			caname = session.getCAInfo(admin, caid).getName();
			
		} catch (javax.ejb.CreateException e) {
			throw new javax.ejb.EJBException(e);
		}
		
		return caname;
	}
	
	public static String getEndEntityProfileName(Admin admin,int profileid){
		String name;
	    
		try {
			ServiceLocator locator = ServiceLocator.getInstance();
			IRaAdminSessionLocalHome home = (IRaAdminSessionLocalHome) locator.getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
			IRaAdminSessionLocal session = home.create();
			name = session.getEndEntityProfileName(admin, profileid);			
		} catch (javax.ejb.CreateException e) {
			throw new javax.ejb.EJBException(e);
		}
		
		return name;
		
	}
	
	public static String getCertificateProfileName(Admin admin,int profileid){
		String name;
	    
		try {
			ServiceLocator locator = ServiceLocator.getInstance();
			ICertificateStoreSessionLocalHome home = (ICertificateStoreSessionLocalHome) locator.getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
			ICertificateStoreSessionLocal session = home.create();
			name = session.getCertificateProfileName(admin, profileid);			
		} catch (javax.ejb.CreateException e) {
			throw new javax.ejb.EJBException(e);
		}
		
		return name;		
	}
		
	public static ApprovalDataText getTokenName(Admin admin,int tokenid){
		ApprovalDataText retval;
	    
		try {
			if(tokenid <= SecConst.TOKEN_SOFT  ){
				int tokenindex=0;
				for(int i=0;i<SecConst.TOKENIDS.length;i++){					
					if(SecConst.TOKENIDS[i] == tokenid){
                      tokenindex = i;								
					}
				}
				retval = new ApprovalDataText("TOKEN" ,SecConst.TOKENTEXTS[tokenindex],true,true);
				
			}else{			
			  ServiceLocator locator = ServiceLocator.getInstance();
			  IHardTokenSessionLocalHome home = (IHardTokenSessionLocalHome) locator.getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
			  IHardTokenSessionLocal session = home.create();
			  String name = session.getHardTokenProfileName(admin, tokenid);
			  retval = new ApprovalDataText("TOKEN" ,name,true,false);
			}
		} catch (javax.ejb.CreateException e) {
			throw new javax.ejb.EJBException(e);
		}
		
		return retval;		
	}

	public static String getHardTokenIssuerName(Admin admin,int issuerid){
		String name;
	    
		try {
			ServiceLocator locator = ServiceLocator.getInstance();
			IHardTokenSessionLocalHome home = (IHardTokenSessionLocalHome) locator.getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
			IHardTokenSessionLocal session = home.create();
			name = session.getHardTokenIssuerAlias(admin, issuerid);		
		} catch (javax.ejb.CreateException e) {
			throw new javax.ejb.EJBException(e);
		}
		
		return name;		
	}

}
