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
 
package se.anatom.ejbca.ca.caadmin;

import java.io.Serializable;

/**
 * Holds nonsensitive information about a null CAToken. Used by processed external CAs not having any keys.
 *
 * @version $Id: NullCATokenInfo.java,v 1.2 2004-04-16 07:38:58 anatom Exp $
 */
public class NullCATokenInfo extends CATokenInfo implements Serializable {    
       
    public NullCATokenInfo(){}
    

}
