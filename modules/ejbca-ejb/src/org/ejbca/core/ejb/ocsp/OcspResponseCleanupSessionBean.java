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
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.config.GlobalConfiguration;

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

    private static final String JOB_NAME = "OcspResponseCleanup";
    private static final String RESCHEDULED_JOB_SUFFIX = "Rescheduled";

    // Fallback for when configured interval is not valid.
    private static final long DEFAULT_RESCHEDULE_INTERVAL = TimeUnit.MINUTES.toMillis(30);
    private static final ScheduleExpression DEFAULT_SCHEDULE = new ScheduleExpression().second("0").minute("0").hour("*/3");

    private TimerService timerService;

    @Resource
    private SessionContext sessionContext;

    @EJB
    private OcspDataSessionLocal ocspDataSession;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

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

                addRescheduledTimer(DEFAULT_RESCHEDULE_INTERVAL, timer.getInfo().toString());
            } else {
                log.warn("Rescheduled timer failed for " + timer.getInfo().toString() + " ", t);
            }
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void start() {
        if (useOcspCleanup()) {
            log.info("OCSP clean up job with configured schedule starting.");
            startJob(getCleanupSchedule());
        } else {
            log.info("OCSP clean up job is disabled.");
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void start(ScheduleExpression expression) {
        log.info("OCSP clean up job with specific schedule started.");

        startJob(expression);
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
        log.info("OCSP response cleanup job has following schedule: " + expression.toString());
        addScheduledTimer(expression);
    }

    private boolean useOcspCleanup() {
        GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);

        return config.getOcspCleanupUse();
    }

    private ScheduleExpression getCleanupSchedule() {
        GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);

        try {
            final Integer schedule = Integer.valueOf(config.getOcspCleanupSchedule());
            final String scheduleUnit = config.getOcspCleanupScheduleUnit();

            if (isDays(scheduleUnit)) {
                return OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.DAYS.toMillis(schedule));
            }

            if (isHours(scheduleUnit)) {
                return OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.HOURS.toMillis(schedule));
            }

            if (isMinutes(scheduleUnit)) {
                return OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.MINUTES.toMillis(schedule));
            }

        } catch (NumberFormatException e) {
            log.warn("Custom schedule could not be converted. Using default schedule: ", e);
            return DEFAULT_SCHEDULE;
        }

        return DEFAULT_SCHEDULE;
    }

    private boolean isDays(String timeUnit) {
        return timeUnit.toUpperCase().equals(TimeUnit.DAYS.toString());
    }

    private boolean isHours(String timeUnit) {
        return timeUnit.toUpperCase().equals(TimeUnit.HOURS.toString());
    }

    private boolean isMinutes(String timeUnit) {
        return timeUnit.toUpperCase().equals(TimeUnit.MINUTES.toString());
    }


    /**
     * Add a single action rescheduled timer.
     *
     * @param interval waiting time for the timer
     * @return Timer
     */
    private Timer addRescheduledTimer(long interval, String timerInfo) {
        String info = timerInfo + "_" + RESCHEDULED_JOB_SUFFIX;

        log.trace(">addTimer for " + info + ". Scheduled: " + interval + "ms");
        return timerService.createSingleActionTimer(interval, new TimerConfig(timerInfo, false));
    }

    /**
     * Add a scheduled timer.
     *
     * @param expression schedule for running the timer
     * @return Timer
     */
    private Timer addScheduledTimer(ScheduleExpression expression) {
        String timerInfo = JOB_NAME;

        log.trace(">addScheduledTimer for " + timerInfo + ". Scheduled: " + expression.toString());
        return timerService.createCalendarTimer(expression, new TimerConfig(timerInfo, false));
    }

    private int cleanUpOcspResponses() {
        try {
            return ocspDataSession.deleteOldOcspData();
        } catch (Exception ex) {
            log.warn("OCSP cleanup job has failed: ", ex);
            return 0;
        }
    }
}