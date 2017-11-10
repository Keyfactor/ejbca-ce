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

    /**
     * Low-level method to convert between a UserDataVOWS data structure from the web service to an EndEntityInformation.
     * This method does not perform any verification and the method {@link #convertUserDataVOWS(AuthenticationToken, UserDataVOWS)}is preferred 
     * as it performs sanity checks that profiles and CAs exist.
     * 
     * @param userdata UserDataVOWS from the WS
     * @param caid CA ID
     * @param endentityprofileid End Entity Profile ID
     * @param certificateprofileid Certificate Profile ID
     * @param hardtokenissuerid Hard Token Issuer ID, or 0 to not use.
     * @param tokenid Token type, TOKEN_TYPE_* constant
     * @param useRawSubjectDN if true ExtendedInformation in the returned EndEntityInformation will be populated with the Raw subject DN from the UserDataVOWS
     * @return New EndEntityInformation object
     * @throws EjbcaException if there are errors in the UserDataVOWS, such as incorrectly formatted validity dates.
     */
    EndEntityInformation convertUserDataVOWSInternal(final UserDataVOWS userdata, final int caid, final int endentityprofileid, final int certificateprofileid, final int hardtokenissuerid, final int tokenid, final boolean useRawSubjectDN) throws EjbcaException;
    
    /**
     * Method to convert between a UserDataVOWS data structure from the web service to an EndEntityInformation.
     * @param admin Authentication token. Used when looking up CA and profile IDs.
     * @param userdata UserDataVOWS from the WS
     * @return New EndEntityInformation object
     * @throws CADoesntExistsException If the CA referenced by the UserDataVOWS does not exist
     * @throws EjbcaException if any of the referenced profiles does not exist, or there are other errors in the UserDataVOWS object, such as incorrectly formatted validity dates.
     */
    EndEntityInformation convertUserDataVOWS(final AuthenticationToken admin, final UserDataVOWS userdata) throws CADoesntExistsException, EjbcaException;
    
    /**
     * Low-level method that converts an EndEntityInformation object to a UserDataVOWS.
     * Used in tests.
     * @param endEntityInformation EndEntityInformation object to convert to a UserDataVOWS
     * @param caname Name of CA. Will be used as is to the UserDataVOWS object.
     * @param endentityprofilename Name of end entity profile. Will be used as is to the UserDataVOWS object.
     * @param certificateprofilename Name of certificate profile. Will be used as is to the UserDataVOWS object.
     * @param hardtokenissuername Name of hard token issuer. Will be used as is to the UserDataVOWS object.
     * @param tokenname Token type name. Will be used as is to the UserDataVOWS object.
     * @return New UserDataVOWS object
     */
    UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation, final String caname, final String endentityprofilename, 
            final String certificateprofilename, final String hardtokenissuername, final String tokenname);
    
    /**
     * Method that converts an EndEntityInformation object to a UserDataVOWS.
     * Used in the findUser and findUserData calls.
     * @param endEntityInformation EndEntityInformation object to convert to a UserDataVOWS
     * @return New UserDataVOWS object
     * @throws EjbcaException if any of the profiles or the hard token issuer referenced by the EndEntityInformation does not exist
     * @throws CADoesntExistsException if the CA referenced by the EndEntityInformation does not exist
     */
    UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation) throws EjbcaException, CADoesntExistsException;
    
}
