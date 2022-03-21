/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.its.EtsiEcaOperationsSessionLocal;
import org.ejbca.core.ejb.its.EtsiEcaOperationsSessionRemote;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EtsiEcaOperationsSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EtsiEcaOperationsSessionBean implements EtsiEcaOperationsSessionLocal, EtsiEcaOperationsSessionRemote {

    @Override
    public byte[] doEtsiOperation(AuthenticationToken authenticationToken, String ecaCertificateId, 
                    byte[] requestBody, int operationCode)
            throws AuthorizationDeniedException, EjbcaException {
        throw new UnsupportedOperationException("ECA operations are only supported in EJBCA Enterprise");
    }

}
