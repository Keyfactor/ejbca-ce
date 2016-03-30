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

package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;



/**
 * Helper class for the View End Entity Page, parses the request and performs appropriate actions.
 * 
 * @version $Id$
 */

public class ViewEndEntityHelper implements Serializable{

	
	private static final long serialVersionUID = 7172234379584156296L;
    public static final String USER_PARAMETER                = "username";
	public static final String TIMESTAMP_PARAMETER           = "timestamp";
	
	public static final String BUTTON_CLOSE                  = "buttonclose";
	public static final String BUTTON_VIEW_NEWER             = "buttonviewnewer";
	public static final String BUTTON_VIEW_OLDER             = "buttonviewolder";
	
	public static final String ACTION                        = "action";
	public static final String ACTION_PAGE                   = "actionpage";
	
	public static final String HIDDEN_USERNAME               = "hiddenusername";
	public static final String HIDDEN_INDEX                  = "hiddenindex";
	
	public static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
	public static final String CHECKBOX_ADMINISTRATOR              = "checkboxadministrator";
	public static final String CHECKBOX_KEYRECOVERABLE             = "checkboxkeyrecoverable";
	public static final String CHECKBOX_SENDNOTIFICATION           = "checkboxsendnotification";
	public static final String CHECKBOX_PRINT                      = "checkboxprint";
	
	public static final String TEXTFIELD_CARDNUMBER                 = "textfieldcardnumber";

	
	public static final String CHECKBOX_VALUE             = "true";

	public static final   int[] statusids = {EndEntityConstants.STATUS_NEW ,EndEntityConstants.STATUS_FAILED, EndEntityConstants.STATUS_INITIALIZED, EndEntityConstants.STATUS_INPROCESS
        , EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_REVOKED , EndEntityConstants.STATUS_HISTORICAL, EndEntityConstants.STATUS_KEYRECOVERY};
	
	public static final   String[] statustexts         = {"STATUSNEW", "STATUSFAILED", "STATUSINITIALIZED", "STATUSINPROCESS", "STATUSGENERATED", "STATUSREVOKED", "STATUSHISTORICAL", "STATUSKEYRECOVERY"};
	
	public static final int columnwidth = 330;
	
	public boolean nouserparameter          = true;
	public boolean notauthorized            = false;	
	public boolean profilenotfound          = true;

	public UserView   userdata = null;
	public UserView[] userdatas = null;
	public String   username = null;
	public EndEntityProfile  profile  = null;
	public int[]  fielddata  = null;
	public String fieldvalue = null;
	
	public int row = 0;
	
	public int currentuserindex = 0;
	
	public String[] tokentexts = RAInterfaceBean.tokentexts;
	public int[] tokenids = RAInterfaceBean.tokenids;
	   
	private boolean initialized;

	private RAInterfaceBean rabean;
	private EjbcaWebBean ejbcawebbean;
	private CAInterfaceBean cabean;
	private String currentusername=null;
	
	
	   // Public methods.
    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(EjbcaWebBean ejbcawebbean,  
    		               RAInterfaceBean rabean, CAInterfaceBean cabean) throws  Exception{

      if(!initialized){

        this.rabean = rabean;
        this.ejbcawebbean = ejbcawebbean;
        this.cabean = cabean;
        initialized = true;
        
        if(ejbcawebbean.getGlobalConfiguration().getIssueHardwareTokens()){
            TreeMap<String, Integer> hardtokenprofiles = ejbcawebbean.getInformationMemory().getHardTokenProfiles();

            tokentexts = new String[RAInterfaceBean.tokentexts.length + hardtokenprofiles.keySet().size()];
            tokenids   = new int[tokentexts.length];
            for(int i=0; i < RAInterfaceBean.tokentexts.length; i++){
              tokentexts[i]= RAInterfaceBean.tokentexts[i];
              tokenids[i] = RAInterfaceBean.tokenids[i];
            }
            Iterator<String> iter = hardtokenprofiles.keySet().iterator();
            int index=0;
            while(iter.hasNext()){       
              String name = (String) iter.next();
              tokentexts[index+RAInterfaceBean.tokentexts.length]= name;
              tokenids[index+RAInterfaceBean.tokentexts.length] = ((Integer) hardtokenprofiles.get(name)).intValue();
              index++;
            }
         }
		
      }
    }
    
    public void parseRequest(HttpServletRequest request) throws AuthorizationDeniedException, Exception{
    	  nouserparameter=true;
    	  notauthorized = false;
    	  profilenotfound = true;
    	  
          RequestHelper.setDefaultCharacterEncoding(request);
    	  String action = request.getParameter(ACTION);
    	  if( action == null  && request.getParameter(TIMESTAMP_PARAMETER) != null &&  request.getParameter(USER_PARAMETER) != null){    		  
    		  username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
    		  Date timestamp = new Date(Long.parseLong(request.getParameter(TIMESTAMP_PARAMETER)));
    		      		      		  
    	      notauthorized = !getUserDatas(username);
    	      currentuserindex = this.getTimeStampIndex(timestamp);
    	      if ( userdatas == null || userdatas.length < 1 ) {
    			  throw new ServletException("Could not find any history for this user.");
    	      }
			  userdata = userdatas[currentuserindex];
    	      
    		  nouserparameter = false;
    		  if(userdata!=null) {
    			  profile = rabean.getEndEntityProfile(userdata.getEndEntityProfileId());
    		  }
    	  }else{ 
    		  if(action  == null && request.getParameter(USER_PARAMETER) != null){    		  
    			  username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");    			
    			  notauthorized = !getUserDatas(username);
    			  nouserparameter = false;
    			  if ( (userdatas != null) && (userdatas.length > 0) ) {
        			  userdata = userdatas[0];
        			  currentuserindex = 0;
        			  if(userdata!=null) {
        				  profile = rabean.getEndEntityProfile(userdata.getEndEntityProfileId());
        			  }
    			  }
    		  }else{
				  
    			  if( action != null && request.getParameter(USER_PARAMETER)!=null){
        			  username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
    				  if(request.getParameter(BUTTON_VIEW_NEWER)!=null){
    					  if(currentuserindex>0){
    						  currentuserindex--;
    					  }	  
    				  }
    				  if(request.getParameter(BUTTON_VIEW_OLDER)!=null){
    					  if(currentuserindex +1<userdatas.length){
    						  currentuserindex++;
    					  }	  
    				  }
    				  
    				  notauthorized  = !getUserDatas(username);
    				  userdata = userdatas[currentuserindex];
    				  
        			  nouserparameter = false;
        			  if(userdata!=null) {
        				  profile = rabean.getEndEntityProfile(userdata.getEndEntityProfileId());
        			  }
    			  }
    		  }
    	  }
    	  
    	  if(profile!=null){
    		  profilenotfound=false;
    	  }
    }

    
    /* returns false if the admin isn't authorized to view user
     * Sets the vaiable userdatas of current and previous values
     */
    
    private boolean getUserDatas(String username) throws Exception{
      boolean authorized = false;	
    
      try{
    	  if(currentusername == null || !currentusername.equals(username)){
    		  // fetch userdata and certreqdatas and order them by timestamp, newest first.
    		  int currentexists = 0;
    		  UserView currentuser = rabean.findUser(username);
    		  if(currentuser != null){
    			  currentexists = 1;  
    		  }
    		  List<CertReqHistory> hist = cabean.getCertReqUserDatas(username);
    		  
    		  userdatas = new UserView[hist.size() +currentexists];
    		  
    		  if(currentuser != null){
    		    userdatas[0] = currentuser;    		  
    		  }
    		  for(int i=0; i< hist.size();i++){
    			  CertReqHistory next = ((CertReqHistory) hist.get(i));
    			  userdatas[i+currentexists] = new UserView(next.getEndEntityInformation(),ejbcawebbean.getInformationMemory().getCAIdToNameMap());
    		  }
			  
    	  }
    	  authorized=true;
	  } catch(AuthorizationDeniedException e){ }            
      return authorized;
    }
    
    /**
     * Returns an Index to the user that related to a certain timestamp.
     * 
     * @param timestamp parameter sent from view log page
     * @return index in user datas that should be shown.
     */
    private int getTimeStampIndex(Date timestamp){
    	int i;
    	
    	for(i=0;i< userdatas.length;i++){
    			if(timestamp.after(userdatas[i].getTimeModified())||
    					timestamp.equals(userdatas[i].getTimeModified())){
    				break;	
    			}
    	}
    	
    	return i;
    }
    
    
}
