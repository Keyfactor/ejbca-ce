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
 
package org.ejbca.core.model.ca.catoken;

import java.io.Serializable;

/**
 * Holds nonsensitive information about a null CAToken. Used by processed external CAs not having any keys.
 *
 * @version $Id$
 */
public class NullCATokenInfo extends CATokenInfo implements Serializable {    
       
    public NullCATokenInfo(){
    	super();
    	setClassPath(NullCAToken.class.getName());
    }
    

}
