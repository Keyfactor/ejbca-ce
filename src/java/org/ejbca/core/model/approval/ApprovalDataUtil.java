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
package org.ejbca.core.model.approval;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.cesecore.util.Base64;

/**
 * Class containing utils for extracting data from the approvaldata table.
 * is used by the Entity and Session bean only.
 * 
 * @version $Id$
 */
public class ApprovalDataUtil  { 
	
	private static final Logger log = Logger.getLogger(ApprovalDataUtil.class);

	public static Collection<Approval> getApprovals(String stringdata) {
    	ArrayList<Approval> retval = new ArrayList<Approval>();
    	try{
    		ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(stringdata.getBytes())));
    		int size = ois.readInt();
    		for(int i=0;i<size;i++){
    			Approval next = (Approval) ois.readObject();
    			retval.add(next);
    		}
    	} catch (IOException e) {
    		log.error("Error building approvals.",e);
    		throw new EJBException(e);
    	} catch (ClassNotFoundException e) {
    		log.error("Error building approvals.",e);
    		throw new EJBException(e);
    	}
    	return retval;
    }
    
    public static ApprovalRequest getApprovalRequest(String stringdata) {
    	ApprovalRequest retval = null;    	
    	try {
    		ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(stringdata.getBytes())));
			retval= (ApprovalRequest) ois.readObject();
		} catch (IOException e) {
			log.error("Error building approval request.",e);
			throw new EJBException(e);
		} catch (ClassNotFoundException e) {
			log.error("Error building approval request.",e);
			throw new EJBException(e);
		}
		return retval;
    }
}
