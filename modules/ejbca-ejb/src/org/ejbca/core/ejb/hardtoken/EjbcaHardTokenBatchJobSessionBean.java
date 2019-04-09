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

package org.ejbca.core.ejb.hardtoken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Used by hardtoken batch clients to retrieve users to generate from EJBCA RA.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "HardTokenBatchJobSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EjbcaHardTokenBatchJobSessionBean implements HardTokenBatchJobSessionRemote, HardTokenBatchJobSessionLocal  {

    public static final int MAX_RETURNED_QUEUE_SIZE = 300;

    private static final Logger log = Logger.getLogger(EjbcaHardTokenBatchJobSessionBean.class);
    
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    
    @EJB
    private HardTokenSessionLocal hardTokenSession;

    @Override
    public EndEntityInformation getNextHardTokenToGenerate(String alias) {
    	log.trace(">getNextHardTokenToGenerate()");
    	EndEntityInformation returnval = null;
    	if (log.isDebugEnabled()) {
    		log.debug("alias=" + alias);
    	}
    	int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    	if (log.isDebugEnabled()) {
    		log.debug("hardTokenIssuerId=" + hardTokenIssuerId);
    	}
    	if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
    		try {
    			List<UserData> userDataList = endEntityAccessSession.findNewOrKeyrecByHardTokenIssuerId(hardTokenIssuerId, 0);
    			if (!userDataList.isEmpty()) {
    				returnval = userDataList.get(0).toEndEntityInformation();
    				if (log.isDebugEnabled()) {    					
    					log.debug("found user" + returnval.getUsername());
    				}
    				String msg = intres.getLocalizedMessage("hardtoken.userdatasent", alias);
    				log.info(msg);
    			}
    		} catch(Exception e) {
    			String msg = intres.getLocalizedMessage("hardtoken.errorsenduserdata", alias);   
    			log.info(msg, e);
    			throw new EJBException(e);
    		}
    	}
    	log.trace("<getNextHardTokenToGenerate()");
    	return returnval;
    }

    @Override
    public Collection<EndEntityInformation> getNextHardTokensToGenerate(String alias) {
    	log.trace(">getNextHardTokensToGenerate()");
    	List<EndEntityInformation> returnval = new ArrayList<EndEntityInformation>();
    	int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    	if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
    		try {
    			List<UserData> userDataList = endEntityAccessSession.findNewOrKeyrecByHardTokenIssuerId( hardTokenIssuerId, MAX_RETURNED_QUEUE_SIZE);
    			for (UserData userData : userDataList) {
    				EndEntityInformation endEntityInformation = userData.toEndEntityInformation();
    				returnval.add(endEntityInformation);
    				String msg = intres.getLocalizedMessage("hardtoken.userdatasent", alias);
    				log.info(msg);
    			}
    		} catch(Exception e) {
    			String msg = intres.getLocalizedMessage("hardtoken.errorsenduserdata", alias);
    			log.info(msg, e);
    			throw new EJBException(e);
    		}
    	}
    	if (returnval.size()==0) {
    		returnval=null;
    	}
    	log.trace("<getNextHardTokensToGenerate()");
    	return returnval;
    }

    // TODO: Since there is no guarantee that the database query always will return entries in the same order, this functionality might be broken!
    @Override
    public EndEntityInformation getNextHardTokenToGenerateInQueue(String alias, int index) {
    	log.trace(">getNextHardTokenToGenerateInQueue()");
    	EndEntityInformation returnval = null;
    	int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    	if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
    		try {
    			List<UserData> userDataList = endEntityAccessSession.findNewOrKeyrecByHardTokenIssuerId(hardTokenIssuerId, 0);
    			if (userDataList.size()>(index-1)) {
    				returnval = userDataList.get(index-1).toEndEntityInformation();
    				String msg = intres.getLocalizedMessage("hardtoken.userdatasent", alias);
    				log.info(msg);
    			}
    		} catch(Exception e) {
    			String msg = intres.getLocalizedMessage("hardtoken.errorsenduserdata", alias);
    			log.info(msg, e);
    			throw new EJBException(e);
    		}
    	}
    	log.trace("<getNextHardTokenToGenerateInQueue()");
    	return returnval;
    }

    @Override
    public int getNumberOfHardTokensToGenerate(String alias){
    	log.trace(">getNumberOfHardTokensToGenerate()");
    	long count = 0;
    	int hardTokenIssuerId = hardTokenSession.getHardTokenIssuerId(alias);
    	if (hardTokenIssuerId != HardTokenSessionBean.NO_ISSUER) {
    		count = endEntityAccessSession.countNewOrKeyrecByHardTokenIssuerId(hardTokenIssuerId);
    	}
    	log.trace("<getNumberOfHardTokensToGenerate()");
    	return (int)count;
    }

    @Override
    public boolean checkForHardTokenIssuerId(int hardtokenissuerid){
    	if (log.isTraceEnabled()) {
            log.trace(">checkForHardTokenIssuerId(id: " + hardtokenissuerid + ")");
    	}
    	return endEntityAccessSession.countByHardTokenIssuerId(hardtokenissuerid) > 0;
    }
}
