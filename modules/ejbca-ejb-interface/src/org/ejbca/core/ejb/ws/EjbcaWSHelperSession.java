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
package org.ejbca.core.ejb.ws;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;

/**
 * @version $Id$
 */
public interface EjbcaWSHelperSession {

    EndEntityInformation convertUserDataVOWS(final UserDataVOWS userdata, final int caid, final int endentityprofileid, final int certificateprofileid, final int hardtokenissuerid, final int tokenid) throws EjbcaException;
    
    EndEntityInformation convertUserDataVOWS(final AuthenticationToken admin, final UserDataVOWS userdata) throws CADoesntExistsException, EjbcaException;
    
    UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation, final String caname, final String endentityprofilename, 
            final String certificateprofilename, final String hardtokenissuername, final String tokenname);
    
    UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation) throws EjbcaException, CADoesntExistsException;
    
}
