package se.anatom.ejbca.admin;

import javax.naming.*;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome;
import se.anatom.ejbca.log.Admin;


/**
 * Base for Commands, contains useful functions
 *
 * @version $Id: BaseCommand.java,v 1.2 2004-04-15 13:45:01 anatom Exp $
 */
public abstract class BaseCommand {
    /** Log4j instance for Base */
    private static Logger baseLog = Logger.getLogger(BaseCommand.class);

    /** Log4j instance for actual class */
    private Logger log;

    /** Cached initial context to save JNDI lookups */
    private static InitialContext cacheCtx = null;
    protected Admin administrator = null;

    /**
     * Creates a new instance of the class
     *
     */
    public BaseCommand() {
        log = Logger.getLogger(this.getClass());
        administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
    }

    /**
     * Method checking if the application server is running.
     * 
     * @return true if app server is running.
     */
	protected boolean appServerRunning() {
		// Check that the application server is running by getting a home interface for user admin session
		try {
	        Context ctx = getInitialContext();
			ICAAdminSessionHome home = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"),ICAAdminSessionHome.class);
			return true;
		} catch (Exception e) {
			error("Appserver not running: ", e);
            return false;
        }
	}

    /**
     * Gets InitialContext
     *
     * @return InitialContext
     */
    protected InitialContext getInitialContext() throws NamingException {
        baseLog.debug(">getInitialContext()");
        try {
            if (cacheCtx == null) {
                cacheCtx = new InitialContext();
            }
            baseLog.debug("<getInitialContext()");
            return cacheCtx;
        } catch (NamingException e) {
            baseLog.error("Can't get InitialContext", e);
            throw e;
        }
    } // getInitialContext

    /**
     * Logs a message with priority DEBUG
     *
     * @param msg Message
     */
    public void debug(String msg) {
        log.debug(msg);
    }

    /**
     * Logs a message and an exception with priority DEBUG
     *
     * @param msg Message
     * @param t Exception
     */
    public void debug(String msg, Throwable t) {
        log.debug(msg, t);
    }

    /**
     * Logs a message with priority INFO
     *
     * @param msg Message
     */
    public void info(String msg) {
        log.info(msg);
    }

    /**
     * Logs a message and an exception with priority INFO
     *
     * @param msg Message
     * @param t Exception
     */
    public void info(String msg, Throwable t) {
        log.info(msg, t);
    }

    /**
     * Logs a message with priority ERROR
     *
     * @param msg Message
     */
    public void error(String msg) {
        log.error(msg);
    }

    /**
     * Logs a message and an exception with priority ERROR
     *
     * @param msg Message
     * @param t Exception
     */
    public void error(String msg, Throwable t) {
        log.error(msg, t);
    }
} //BaseCommand
