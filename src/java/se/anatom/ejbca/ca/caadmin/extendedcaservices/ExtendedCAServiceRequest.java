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
 
package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;



/**
 * Should be enherited by all ExtendedCAServiceRequest Value objects.  
 *
 * @version $Id: ExtendedCAServiceRequest.java,v 1.3 2004-04-16 07:38:57 anatom Exp $
 */
public abstract class ExtendedCAServiceRequest  implements Serializable {    
       
    public ExtendedCAServiceRequest(){}    

}
