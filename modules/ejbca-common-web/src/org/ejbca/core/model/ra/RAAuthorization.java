/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * A class that looks up the which CA:s or end entity profiles the administrator is authorized to view.
 * 
 * @version $Id$
 */
public class RAAuthorization implements Serializable {
    
    private static final long serialVersionUID = -3195162814492440326L;
    private String authcastring = null;
    private String authendentityprofilestring = null;
    private TreeMap<String, Integer> authprofilenames = null;
	private List<Integer> authprofileswithmissingcas = null;
    private AuthenticationToken admin;
    private AuthorizationSessionLocal authorizationSession;
    private GlobalConfigurationSession globalConfigurationSession;
    private CaSession caSession;
    private EndEntityProfileSession endEntityProfileSession;
    
    /** Creates a new instance of RAAuthorization. */
    public RAAuthorization(AuthenticationToken admin, GlobalConfigurationSession globalConfigurationSession, AuthorizationSessionLocal authorizationSession, 
                    CaSession caSession, EndEntityProfileSession endEntityProfileSession) {
    	this.admin = admin;
    	this.globalConfigurationSession = globalConfigurationSession;
    	this.authorizationSession = authorizationSession;
    	this.caSession = caSession;
    	this.endEntityProfileSession = endEntityProfileSession;
    }

    private boolean isAuthorizedNoLogging(final AuthenticationToken authenticationToken, String... resources) {
        return authorizationSession.isAuthorizedNoLogging(admin, resources);
    }

    /**
     * Method that checks the administrators CA privileges and returns a string that should be used in where clause of userdata SQL queries.
     *
     * @return a string of administrators CA privileges that should be used in the where clause of SQL queries.
     */
    public String getCAAuthorizationString() {      
        if (authcastring==null) {
            authcastring = "";
            final List<Integer> authorizedCaIds = caSession.getAuthorizedCaIds(admin);
            if (authorizedCaIds.isEmpty()) {
                // Setup a condition that can never be true if there are no authorized CAs
                authcastring = "(0=1)";
            } else {
                for (final Integer caId : caSession.getAuthorizedCaIds(admin)) {
                    if (authcastring.equals("")) {
                        authcastring = " cAId = " + caId.toString();   
                    } else {    
                        authcastring = authcastring + " OR cAId = " + caId.toString();
                    }
                }
                if (!authcastring.isEmpty()) {
                    authcastring = "( " + authcastring + " )"; 
                }
            }
        }
        return authcastring;
    } 
    
    /**
     * @return a string of end entity profile privileges that should be used in the where clause of SQL queries, or null if no authorized end entity profiles exist.
     * @throws AuthorizationDeniedException if the current requester isn't authorized to query for approvals
     */
    public String getEndEntityProfileAuthorizationString(String endentityAccessRule) throws AuthorizationDeniedException {
        boolean authorizedToApproveCAActions = false; // i.e approvals with endentityprofile ApprovalDataVO.ANY_ENDENTITYPROFILE
        boolean authorizedToApproveRAActions = false; // i.e approvals with endentityprofile not ApprovalDataVO.ANY_ENDENTITYPROFILE 
     
        authorizedToApproveCAActions = isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_APPROVECAACTION);

        authorizedToApproveRAActions = isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY);

        if (!authorizedToApproveCAActions && !authorizedToApproveRAActions) {
            throw new AuthorizationDeniedException("Not authorized to query for approvals: "+authorizedToApproveCAActions+", "+authorizedToApproveRAActions);
        }

    	String endentityauth = null;
        GlobalConfiguration globalconfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (globalconfiguration.getEnableEndEntityProfileLimitations()){
        	endentityauth = getEndEntityProfileAuthorizationString(true, endentityAccessRule);
        	if(authorizedToApproveCAActions && authorizedToApproveRAActions){
        		endentityauth = getEndEntityProfileAuthorizationString(true, endentityAccessRule);
        		if(endentityauth != null){
        		  endentityauth = "(" + getEndEntityProfileAuthorizationString(false, endentityAccessRule) + " OR endEntityProfileId=" + ApprovalDataVO.ANY_ENDENTITYPROFILE + " ) ";
        		}
        	}else if (authorizedToApproveCAActions) {
        		endentityauth = " endEntityProfileId=" + ApprovalDataVO.ANY_ENDENTITYPROFILE;
			}else if (authorizedToApproveRAActions) {
				endentityauth = getEndEntityProfileAuthorizationString(true, endentityAccessRule);
			}        	
        	
        }
        return endentityauth == null ? endentityauth : endentityauth.trim();
    }

    /**
     * Method that checks the administrators end entity profile privileges and returns a string that should be used in where clause of userdata SQL queries.
     *
     * @return a string of end entity profile privileges that should be used in the where clause of SQL queries, or null if no authorized end entity profiles exist.
     */
    public String getEndEntityProfileAuthorizationString(boolean includeparanteses, String endentityAccessRule){
        if (authendentityprofilestring==null) {
            final List<Integer> profileIds = new ArrayList<Integer>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(admin, endentityAccessRule));
            if (!endentityAccessRule.startsWith(AccessRulesConstants.VIEW_END_ENTITY)) {
                // Additionally require view access to all the profiles
                for (final Integer profileid : new ArrayList<Integer>(profileIds)) {
                    if (!isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.VIEW_END_ENTITY)) {
                        profileIds.remove(profileid);
                    }
                }
            }
            for (final int profileId : profileIds) {
                if (authendentityprofilestring == null) {
                    authendentityprofilestring = " endEntityProfileId = " + profileId;
                } else {
                    authendentityprofilestring = authendentityprofilestring + " OR endEntityProfileId = " + profileId;
                }
            }
            if (authendentityprofilestring != null && includeparanteses) {
                authendentityprofilestring = "( " + authendentityprofilestring + " )"; 
            }
        }
        return authendentityprofilestring; 
    }
    
    public TreeMap<String, Integer> getAuthorizedEndEntityProfileNames(final String endentityAccessRule){
    	if (authprofilenames==null){
    		authprofilenames = new TreeMap<String, Integer>(new Comparator<String>() {
                @Override
                public int compare(String o1, String o2) {
                    return o1.compareToIgnoreCase(o2);
                }
            });
    		final Map<Integer, String> idtonamemap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
    		for (final Integer id : endEntityProfileSession.getAuthorizedEndEntityProfileIds(admin, endentityAccessRule)) {
    			authprofilenames.put(idtonamemap.get(id), id);
    		}
    	}
    	return authprofilenames;  
    }
    
	public List<Integer> getViewAuthorizedEndEntityProfilesWithMissingCAs() {
	   if (authprofileswithmissingcas == null) {
	       authprofileswithmissingcas = endEntityProfileSession.getAuthorizedEndEntityProfileIdsWithMissingCAs(admin);
	   }
	   return authprofileswithmissingcas;
	}
    
    public void clear(){
      authcastring=null;
      authendentityprofilestring=null;
      authprofilenames = null;
	  authprofileswithmissingcas = null;
    }
    
    /**
     * Help function used to check end entity profile authorization.
     */
    public boolean endEntityAuthorization(AuthenticationToken admin, int profileid, String rights) {
        return isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + Integer.toString(profileid) + rights);
    }  
}


