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
package org.ejbca.core.model.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.intervals.DummyInterval;

/**
 * Abstract base class that initializes the worker and its interval and action.
 *  
 * @version $Id$
 */
public abstract class BaseWorker implements IWorker {

	private static final Logger log = Logger.getLogger(BaseWorker.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    protected Properties properties = null;
    protected String serviceName = null;
    protected ServiceConfiguration serviceConfiguration = null;
    /** The time this service should have been running. Usually this is 'now'. But is the appserver was down it can have been delayed execution */
    protected long runTimeStamp;
    /** The next time the service is scheduled to run */
    protected long nextRunTimeStamp;
    private IAction action = null;
    private IInterval interval = null;
    
    protected AuthenticationToken admin = null;

	private transient Collection<Integer> cAIdsToCheck = null;
	private transient long timeBeforeExpire = -1;

	/**
	 * @see org.ejbca.core.model.services.IWorker#init(org.ejbca.core.model.services.ServiceConfiguration, java.lang.String)
	 */
	public void init(AuthenticationToken admin, ServiceConfiguration serviceConfiguration,
			String serviceName, long runTimeStamp, long nextRunTimeStamp) {
		this.admin = admin;
		this.serviceName = serviceName;
		this.runTimeStamp = runTimeStamp;
		this.nextRunTimeStamp = nextRunTimeStamp;
		this.serviceConfiguration = serviceConfiguration;
		this.properties = serviceConfiguration.getWorkerProperties();
		
		String actionClassPath = serviceConfiguration.getActionClassPath();
		if(actionClassPath != null){
			try {
				action = (IAction) Thread.currentThread().getContextClassLoader().loadClass(actionClassPath).newInstance();
				action.init(serviceConfiguration.getActionProperties(), serviceName);
			} catch (Exception e) {
				String msg = intres.getLocalizedMessage("services.erroractionclasspath", serviceName);
				log.error(msg,e);
			}       
		}else{
			log.debug("Warning no action class i defined for the service " + serviceName);
		}
		
		String intervalClassPath = serviceConfiguration.getIntervalClassPath();
		if(intervalClassPath != null){
			try {
				interval = (IInterval) Thread.currentThread().getContextClassLoader().loadClass(intervalClassPath).newInstance();
				interval.init(serviceConfiguration.getIntervalProperties(), serviceName);
			} catch (Exception e) {
				String msg = intres.getLocalizedMessage("services.errorintervalclasspath", serviceName);
				log.error(msg,e);
			}       
		}else{
			String msg = intres.getLocalizedMessage("services.errorintervalclasspath", serviceName);
			log.error(msg);
		}
		
		if(interval == null){
			interval = new DummyInterval();
		}

	}

	
	/**
	 * @see org.ejbca.core.model.services.IWorker#getNextInterval()
	 */
	public long getNextInterval() {		
		return interval.getTimeToExecution();
	}
	
	protected IAction getAction(){
		if(action == null){
			String msg = intres.getLocalizedMessage("services.erroractionclasspath", serviceName);
			log.error(msg);
		}
		return action;
	}
	
	/**
	 * Returns the admin that should be used for other calls.
	 */
	protected AuthenticationToken getAdmin(){
		return admin;
	}
	
    /**
     * Returns the amount of time, in milliseconds that the expire time of
     * configured for
     */
    protected long getTimeBeforeExpire() throws ServiceExecutionFailedException {
        if (timeBeforeExpire == -1) {
            String unit = properties.getProperty(PROP_TIMEUNIT);
            if (unit == null) {
                String msg = intres.getLocalizedMessage("services.errorexpireworker.errorconfig", serviceName, "UNIT");
                throw new ServiceExecutionFailedException(msg);
            }
            int unitval = 0;
            for (int i = 0; i < AVAILABLE_UNITS.length; i++) {
                if (AVAILABLE_UNITS[i].equalsIgnoreCase(unit)) {
                    unitval = AVAILABLE_UNITSVALUES[i];
                    break;
                }
            }
            if (unitval == 0) {
                String msg = intres.getLocalizedMessage("services.errorexpireworker.errorconfig", serviceName, "UNIT");
                throw new ServiceExecutionFailedException(msg);
            }


            int intvalue = 0;
            try {
                intvalue = Integer.parseInt(properties.getProperty(PROP_TIMEBEFOREEXPIRING));
            } catch (NumberFormatException e) {
                String msg = intres.getLocalizedMessage("services.errorexpireworker.errorconfig", serviceName, "VALUE");
                throw new ServiceExecutionFailedException(msg);
            }

            if (intvalue == 0) {
                String msg = intres.getLocalizedMessage("services.errorexpireworker.errorconfig", serviceName, "VALUE");
                throw new ServiceExecutionFailedException(msg);
            }
            timeBeforeExpire = intvalue * unitval;
        }

        return timeBeforeExpire * 1000;
    }

	/** returns a collection of String with CAIds as gotten from the property  BaseWorker.PROP_CAIDSTOCHECK.
	 * @param includeAllCAsIfNull set to true if the 'catch all' SecConst.ALLCAS should be included in the list IF there does not exist a list. This CAId is not recognized by all recipients...
     * This is due to that the feature of selecting CAs was enabled in EJBCA 3.9.1, and we want the service to keep working even after an upgrade from an earlier version.
	 * 
	 * @return Collection<String> of integer CA ids in String form, use Integer.valueOf to convert to int.
	 */
	protected Collection<Integer> getCAIdsToCheck(boolean includeAllCAsIfNull) throws ServiceExecutionFailedException {
		if(cAIdsToCheck == null){
			cAIdsToCheck = new ArrayList<Integer>();
			String cas = properties.getProperty(PROP_CAIDSTOCHECK);
		    if (log.isDebugEnabled()) {
		    	log.debug("CAIds to check: "+cas);
		    }
			if (cas != null) {
				String[] caids = cas.split(";");
				for(int i=0;i<caids.length;i++ ){
					try {
						Integer.valueOf(caids[i]);
					} catch (Exception e) {
						String msg = intres.getLocalizedMessage("services.errorexpireworker.errorconfig", serviceName, PROP_CAIDSTOCHECK);
						throw new ServiceExecutionFailedException(msg, e);						
					}
					cAIdsToCheck.add(Integer.valueOf(caids[i]));
				}				
			} else if (includeAllCAsIfNull) {
				cAIdsToCheck.add(Integer.valueOf(SecConst.ALLCAS));
			}
		}
		return cAIdsToCheck;
	}
}
