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
 
package se.anatom.ejbca.admin;

import java.io.PrintStream;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.util.InitialContextBuilder;

/**
 * Base for all AdminCommands, contains functions for getting initial context and logging
 *
 * @version $Id: BaseAdminCommand.java,v 1.11 2004-10-13 07:14:46 anatom Exp $
 */
public abstract class BaseAdminCommand implements IAdminCommand {
    /** Log4j instance for Base */
    private static Logger baseLog = Logger.getLogger(BaseAdminCommand.class);

    /** Log4j instance for actual class */
    private Logger log;

    /** Where print output of commands */
    private PrintStream outStream = System.out;

    /** holder of argument array */
    protected String[] args = null;

    /**
     * Initialize a new instance of BaseAdminCommand
     *
     * @param args command line arguments
     * @param outStream stream where commands write its output
     */
    private void Init(String[] args, PrintStream outStream) {
        log = Logger.getLogger(this.getClass());
        this.args = args;
        if( outStream != null ) {
          this.outStream = outStream;
        }
    }

    /**
     * Creates a new instance of BaseAdminCommand
     *
     * @param args command line arguments
     * @param outStream stream where commands write its output
     */
    public BaseAdminCommand(String[] args, PrintStream outStream) {
	Init(args,outStream);
    }

    /**
     * Creates a new instance of BaseAdminCommand
     *
     * @param args command line arguments
     */
    public BaseAdminCommand(String[] args) {
	Init(args,null);
    }

    /**
     * Gets InitialContext
     *
     * @return InitialContext
     */
    protected InitialContext getInitialContext() throws NamingException {
        baseLog.debug(">getInitialContext()");

        try {
        	InitialContext cacheCtx = InitialContextBuilder.getInstance().getInitialContext();
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


    /**
     * Return the PrintStream used to print output of commands
     *
     */
    public PrintStream getOutputStream() {
	return outStream;
    }

    /**
     * Set the PrintStream used to print output of commands
     *
     * @param outStream stream where commands write its output
     */
    public void setOutputStream(PrintStream outStream) {
	if( outStream == null )
		this.outStream = System.out;
	else
		this.outStream = outStream;
    }	

}


//BaseAdminCommand
