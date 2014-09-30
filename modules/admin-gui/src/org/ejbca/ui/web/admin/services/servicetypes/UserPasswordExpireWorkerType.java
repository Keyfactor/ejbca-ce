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
package org.ejbca.ui.web.admin.services.servicetypes;

import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;


/**
 * Class managing the view of the Certificate Exiration Notifier Worker
 * 
 * @author Philip Vendil, Tomas Gustavsson
 *
 * @version $Id$
 */
public class UserPasswordExpireWorkerType extends BaseEmailNotifyingWorkerType {

	private static final long serialVersionUID = -3242483317114929799L;
    public static final String NAME = "USERPASSWORDEXPIREWORKER";
	
	public UserPasswordExpireWorkerType(){
		super(NAME, "userpasswordexpireworker.jsp", UserPasswordExpireWorker.class.getName());
	}
}
