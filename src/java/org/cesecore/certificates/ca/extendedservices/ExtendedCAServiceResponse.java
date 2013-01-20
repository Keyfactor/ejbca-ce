/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca.extendedservices;

import java.io.Serializable;

/**
 * Should be inherited by all ExtendedCAServiceResonse Value objects.  
 *
 * @version $Id$
 */
public abstract class ExtendedCAServiceResponse  implements Serializable {    
       
    private static final long serialVersionUID = -620664487119094080L;

    public ExtendedCAServiceResponse(){}    

}
