package se.anatom.ejbca.admin;

import javax.naming.*;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ra.IUserAdminSessionHome;


/**
 * Base for Commands, contains useful functions
 *
 * @version $Id: BaseCommand.java,v 1.1 2004-04-10 17:12:26 anatom Exp $
 */
public abstract class BaseCommand {
    /** Log4j instance for Base */
    private static Logger baseLog = Logger.getLogger(BaseCommand.class);

    /** Log4j instance for actual class */
    private Logger log;

    /**
     * Creates a new instance of the class
     *
     */
    public BaseCommand() {
        log = Logger.getLogger(this.getClass());
    }

    /**
     * Method checking if the application server is running.
     * 
     * @return true if app server is running.
     */
	protected boolean appServerRunning() {
		// Check that the application server is running by getting a home interface for user admin session
		try {
			IUserAdminSessionHome home = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow((new InitialContext()).lookup("UserAdminSession"),IUserAdminSessionHome.class);
			return true;
		} catch (Exception e) {
            return false;
        }
	}

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
