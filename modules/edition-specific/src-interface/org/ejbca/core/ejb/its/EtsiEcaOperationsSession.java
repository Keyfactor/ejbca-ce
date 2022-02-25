package org.ejbca.core.ejb.its;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.EjbcaException;

public interface EtsiEcaOperationsSession {
    
    byte[] enrollItsCredential(AuthenticationToken authenticationToken, byte[] requestBody) 
                                            throws AuthorizationDeniedException;

}
