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
 
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;


/**
 * Class used when requesting hard token encrypt related services from a CA.  
 *
 * @version $Id$
 */
public class HardTokenEncryptCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
 
	private static final long serialVersionUID = 8081402124613587671L;
    public static final int COMMAND_ENCRYPTDATA = 1;
	public static final int COMMAND_DECRYPTDATA = 2;
	
    private int command;
    private byte[] data;

    public HardTokenEncryptCAServiceRequest(int command, byte[] data) {
        this.command = command;
        this.data = data;
    }

    
    public int getCommand(){
    	return command;    	
    }
    
    /**
     *  Returns data beloning to the decrypt keys request, returns null oterwise.
     */
    
    public  byte[] getData(){
    	return data;
    }
    
	@Override
	public int getServiceType() {
		return ExtendedCAServiceTypes.TYPE_HARDTOKENENCEXTENDEDSERVICE;
	}

}
