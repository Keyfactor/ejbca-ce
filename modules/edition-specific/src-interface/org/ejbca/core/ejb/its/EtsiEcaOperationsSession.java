package org.ejbca.core.ejb.its;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.EjbcaException;

public interface EtsiEcaOperationsSession {
    
    byte[] doEtsiOperation(AuthenticationToken authenticationToken, String ecaCertificateId, byte[] requestBody, int operationCode)
            throws AuthorizationDeniedException, EjbcaException;

}
