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
package org.ejbca.core.ejb.ocsp;

import org.apache.log4j.Logger;
import org.cesecore.jndi.JndiConstants;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.ScheduleExpression;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import java.util.concurrent.TimeUnit;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspResponseCleanupSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class OcspResponseCleanupSessionBean implements OcspResponseCleanupSessionLocal, OcspResponseCleanupSessionRemote {

    private static final Logger log = Logger.getLogger(OcspResponseCleanupSessionBean.class);

    private static final String JOB_NAME = "OcspCleanup";
    private static final String RESCHEDULED_JOB_SUFFIX = "Rescheduled";

    private static final long DEFAULT_RESCHEDULE_INTERVAL = TimeUnit.MINUTES.toMillis(30);
    private static final ScheduleExpression DEFAULT_SCHEDULE = new ScheduleExpression().second("0").minute("0").hour("*/3");

    @Resource
    private SessionContext sessionContext;
    private TimerService timerService;

    @EJB
    private OcspDataSessionLocal ocspDataSession;

    @PostConstruct
    public void ejbCreate() {
        timerService = sessionContext.getTimerService();
    }

    @Override
    @Timeout
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
        log.trace(">timeoutHandler@OcspResponseCleanupSessionBean");

        try {
            long start = System.currentTimeMillis();
            int rowsDeleted = cleanUpOcspResponses();

            log.info(String.format("%d OCSP responses cleaned up successfully in %d seconds by %s",
                                   rowsDeleted, TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - start),
                                   timer.getInfo().toString()));
        } catch (Throwable t) {
            // Reschedule a single action timer in case of a generic failure.
            if (timer.isCalendarTimer()) {
                log.warn("OCSP clean up job failed for " + timer.getInfo().toString(), t);

                addTimer(DEFAULT_RESCHEDULE_INTERVAL, timer.getInfo().toString());
            } else {
                log.warn("Rescheduled timer failed for " + timer.getInfo().toString() + " ", t);
            }
        }

    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void start(String callerName) {
        log.info("OCSP clean up job with default schedule started by: " + callerName);

        startJob(callerName, DEFAULT_SCHEDULE);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void start(String callerName, ScheduleExpression expression) {
        log.info("OCSP clean up job started by: " + callerName);

        startJob(callerName, expression);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void stop(String callerName) {
        for (final Timer timer : timerService.getTimers()) {
            if (ownsTimer(timer, callerName)) {
                try {
                    log.info("Timer (" + timer.getInfo().toString() + ") cancelled for " + callerName);

                    timer.cancel();
                } catch (Exception e) {
                    log.info("Exception occured canceling timer: " + e.getMessage());
                }
            }
        }
    }

    @Override
    public boolean hasTimers(String callerName) {
        return timerService.getTimers()
                           .stream()
                           .filter(timer -> ownsTimer(timer, callerName))
                           .count() > 0;
    }

    private void startJob(String callerName, ScheduleExpression expression) {
        if (hasTimers(callerName)) {
            stop(callerName);
        }

        addScheduledTimer(expression, callerName);
    }

    /**
     * Add a single action timer.
     *
     * @param interval waiting time for the timer
     * @param callerName caller name used to build the the timer info
     *
     * @return Timer
     */
    private Timer addTimer(long interval, String callerName) {
        String timerInfo = callerName + "_" + RESCHEDULED_JOB_SUFFIX;

        log.trace(">addTimer for " + timerInfo + ". Scheduled: " + interval + "ms");
        return timerService.createSingleActionTimer(interval, new TimerConfig(timerInfo, false));
    }

    /**
     * Add a scheduled timer.
     * @param expression schedule for running the timer
     * @param callerName caller name used to build the the timer info
     *
     * @return Timer
     */
    private Timer addScheduledTimer(ScheduleExpression expression, String callerName) {
        String timerInfo = callerName + "_" + JOB_NAME;

        log.trace(">addScheduledTimer for " + timerInfo + ". Scheduled: " + expression.toString());
        return timerService.createCalendarTimer(expression, new TimerConfig(timerInfo, false));
    }

    private int cleanUpOcspResponses() {
        return ocspDataSession.deleteOldOcspData();
    }

    private boolean ownsTimer(Timer timer, String callerName) {
        return timer.getInfo().toString().contains(callerName);
    }
}