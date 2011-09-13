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
package org.cesecore.authentication;

import java.util.HashMap;
import java.util.LinkedHashMap;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationProvider;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiConstants;

/**
 * This class implements the Authentication interface. It handles authentication of Subjects.
 * 
 * Based on cesecore version:
 *      AuthenticationSessionBean.java 897 2011-06-20 11:17:25Z johane
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AuthenticationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AuthenticationSessionBean implements AuthenticationSessionLocal, AuthenticationSessionRemote {

    @EJB
    private InternalSecurityEventsLoggerSessionLocal securityEventsLogger;
    
    /**
     * Retrieves an AuthenticationToken from the provided AuthenticationProvider, based on the provided Subject.
     *
     * This method will print to the SecurityEventsLogger
     * 
     * @param subject A Subject to evaluate.
     * @param authenticationProvider An interface to the class which perform the authentication.
     * @return An AuthenticationToken derived from the Subject, or null if authentication fails.
     */
    @Override
    public AuthenticationToken authenticate(final AuthenticationSubject subject, AuthenticationProvider authenticationProvider) {
        AuthenticationToken result = null;
        result = authenticationProvider.authenticate(subject);   
        if(result == null) {
            HashMap<String, Object> message = new LinkedHashMap<String, Object>();
            message.put("message", "Subject " + subject + " could not be authenticated.");
            securityEventsLogger.log(EventTypes.AUTHENTICATION, EventStatus.FAILURE, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE, subject.toString(), null, null, null, message);
        }
     
        return result;
    }

}
