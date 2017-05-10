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
 
package org.ejbca.ui.web.admin.cainterface;

import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;


/**
 * Contains help methods used to parse a viewcainfo jsp page requests.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class ViewCAInfoJSPHelper implements java.io.Serializable {
		 
	private static final long serialVersionUID = 109073226626366410L;

    public static final String CA_PARAMETER             = "caid";

	public static final String CERTSERNO_PARAMETER      = "certsernoparameter"; 
	  
	public static final String PASSWORD_AUTHENTICATIONCODE  = "passwordactivationcode";
	
    public static final String CHECKBOX_VALUE                = BasePublisher.TRUE;
	  
	public static final String BUTTON_ACTIVATE          = "buttonactivate";
	public static final String BUTTON_MAKEOFFLINE       = "buttonmakeoffline";
	public static final String BUTTON_CLOSE             = "buttonclose"; 
	public static final String CHECKBOX_INCLUDEINHEALTHCHECK = "includeinhealthcheck";
	public static final String SUBMITHS					= "submiths";

    private CAInterfaceBean cabean;
    private boolean initialized=false;
	public String   generalerrormessage = null;
	public String   activationerrormessage = null;
	public String   activationerrorreason = null;
	public String   activationmessage = null;
    public CAInfoView cainfo = null;
    public  int status = 0; 
    public boolean tokenoffline = false;
    public  int caid = 0; 

    /** Creates new LogInterfaceBean */
    public ViewCAInfoJSPHelper(){     	    	
    }

    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean, CAInterfaceBean cabean) {
        if (!initialized) {
            this.cabean = cabean;                        		
            initialized = true;
        }
    }

    /**
     * Method that parses the request and take appropriate actions.
     * @param request the http request
     * @throws Exception
     */
    public void parseRequest(HttpServletRequest request) throws Exception {
        generalerrormessage = null;
        activationerrormessage = null;   
        activationmessage = null;
        RequestHelper.setDefaultCharacterEncoding(request);
        if (request.getParameter(CA_PARAMETER) != null){
            caid = Integer.parseInt(request.getParameter(CA_PARAMETER));
            // Get currentstate
            status = CAConstants.CA_OFFLINE;
            try {
                cainfo = cabean.getCAInfo(caid);
                if (cainfo==null) {
                    generalerrormessage = "CADOESNTEXIST";  
                } else {
                    status = cainfo.getCAInfo().getStatus();
                }
            } catch(AuthorizationDeniedException e) {
                generalerrormessage = "NOTAUTHORIZEDTOVIEWCA";
                return;
            } 
        } else {
            generalerrormessage = "YOUMUSTSPECIFYCAID";
        }
    }
}
