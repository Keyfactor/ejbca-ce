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

package org.ejbca.core.protocol.scep;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Resource;
import jakarta.ejb.EJB;
import jakarta.ejb.ScheduleExpression;
import jakarta.ejb.SessionContext;
import jakarta.ejb.Stateless;
import jakarta.ejb.Timeout;
import jakarta.ejb.Timer;
import jakarta.ejb.TimerConfig;
import jakarta.ejb.TimerService;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.transaction.SystemException;
import org.apache.log4j.Logger;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.AvailableProtocolsConfiguration;

@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ScepKeyRenewalSessionBean implements ScepKeyRenewalSessionLocal, ScepKeyRenewalSessionRemote{

	private static final Logger log = Logger.getLogger(ScepKeyRenewalSessionBean.class);

	private static final String JOB_NAME = "ScepKeyRenewal";

	private static final ScheduleExpression DEFAULT_SCHEDULE = new ScheduleExpression().second("0").minute("0").hour("*");

	private TimerService timerService;

	@Resource
	private SessionContext sessionContext;
	@EJB
	private GlobalConfigurationSessionLocal globalConfigSession;
	@EJB
	private ScepKeyRenewalDataSessionLocal scepKeyRenewalDataSession;


	@PostConstruct
	public void ejbCreate() {
		timerService = sessionContext.getTimerService();
	}

	@Override
	@Timeout
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public void timeoutHandler(Timer timer) throws SystemException {
		log.trace(">timeoutHandler@ScepKeyRenewalSessionBean");
		scepKeyRenewalDataSession.renewScepKeys();
		log.info("Renewed keys for SCEP alias");
	}

	@Override
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public void start() {
		if (shouldRenewScep()) {
			log.info("SCEP key renewal job with configured schedule starting.");
			startJob(DEFAULT_SCHEDULE);
		} else {
			log.info("SCEP key renewal job is disabled.");
		}
	}

	@Override
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public void stop() {
		for (final Timer timer : timerService.getTimers()) {
			try {
				log.info("Timer (" + timer.getInfo().toString() + ") is getting cancelled.");
				timer.cancel();
			} catch (Exception e) {
				log.info("Exception occured canceling timer: " + e.getMessage());
			}
		}
	}

	@Override
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public void restart() {
		stop();
		start();
	}

	@Override
	public boolean hasTimers() {
		return timerService.getTimers().size() > 0;
	}

	private void startJob(ScheduleExpression expression) {
		if (hasTimers()) {
			stop();
		}
		log.info("SCEP key renewal job has following schedule: " + expression.toString());
		addScheduledTimer(expression);
	}

	private boolean shouldRenewScep() {
		var protocolConfig = (AvailableProtocolsConfiguration) globalConfigSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
		return protocolConfig.getProtocolStatus("SCEP");
	}

	/**
	 * Add a scheduled timer.
	 *
	 * @param expression schedule for running the timer
	 */
	private void addScheduledTimer(ScheduleExpression expression) {
		log.trace(">addScheduledTimer for " + JOB_NAME + ". Scheduled: " + expression.toString());
		timerService.createCalendarTimer(expression, new TimerConfig(JOB_NAME, false));
	}

}
