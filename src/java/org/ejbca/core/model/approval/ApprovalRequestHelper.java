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

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.util.EjbLocalHelper;



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
			caname = new EjbLocalHelper().getCAAdminSession().getCAInfo(admin, caid).getName();
		} catch (javax.ejb.CreateException e) {
			throw new javax.ejb.EJBException(e);
		}
		
		return caname;
	}
	
    public static String getEndEntityProfileName(Admin admin, int profileid) {
        return new EjbLocalHelper().getEndEntityProfileSession().getEndEntityProfileName(admin, profileid);
    }
	
    public static String getCertificateProfileName(Admin admin, int profileid) {
        String name;
        name = new EjbLocalHelper().getCertificateProfileSession().getCertificateProfileName(admin, profileid);
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
			  String name = new EjbLocalHelper().getHardTokenSession().getHardTokenProfileName(admin, tokenid);
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
			name = new EjbLocalHelper().getHardTokenSession().getHardTokenIssuerAlias(admin, issuerid);
		} catch (javax.ejb.CreateException e) {
			throw new javax.ejb.EJBException(e);
		}
		
		return name;		
	}

}
