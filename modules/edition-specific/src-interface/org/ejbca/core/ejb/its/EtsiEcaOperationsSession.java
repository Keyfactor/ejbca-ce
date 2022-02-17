package org.ejbca.core.ejb.its;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

public interface EtsiEcaOperationsSession {
    
    byte[] enrollItsCredential(AuthenticationToken authenticationToken, byte[] requestBody) throws AuthorizationDeniedException;

}
