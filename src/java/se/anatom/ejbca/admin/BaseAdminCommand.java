
package se.anatom.ejbca.admin;

import javax.naming.*;

import org.apache.log4j.*;

/** Base for all AdminCommands, contains functions for getting initial context and logging
 *
 * @version $Id: BaseAdminCommand.java,v 1.5 2002-05-10 08:29:04 anatom Exp $
 */
public abstract class BaseAdminCommand implements IAdminCommand {

    /** Log4j instance for Base */
    private static Logger baseLog = Logger.getLogger( BaseAdminCommand.class.getName() );
    /** Log4j instance for actual class */
    private Logger log;

    /** Cached initial context to save JNDI lookups */
    private static InitialContext cacheCtx = null;

    /** holder of argument array */
    protected String[] args = null;

    /** Creates a new instance of BaseAdminCommand */
    public BaseAdminCommand(String[] args) {
        log = Logger.getLogger( this.getClass().getName() );
        this.args = args;
    }

    /** Gets InitialContext
     *@return InitialContext
     */
    protected InitialContext getInitialContext() throws NamingException {
        baseLog.debug(">getInitialContext()");
        try {
            if( cacheCtx == null )
                cacheCtx = new InitialContext();
            baseLog.debug("<getInitialContext()");
            return  cacheCtx;
        } catch (NamingException e ) {
            baseLog.error("Can't get InitialContext", e);
            throw e;
        }
    } // getInitialContext

    /** Logs a message with priority DEBUG
     * @param msg Message
     */
    public  void    debug( String msg ) {
        log.debug( msg );
    }
    /** Logs a message and an exception with priority DEBUG
     * @param msg Message
     * @param t Exception
     */
    public  void    debug( String msg, Throwable t ) {
        log.debug( msg, t );
    }
    /** Logs a message with priority INFO
     * @param msg Message
     */
    public  void    info( String msg ) {
        log.info( msg );
    }
    /** Logs a message and an exception with priority INFO
     * @param msg Message
     * @param t Exception
     */
    public  void    info( String msg, Throwable t  ) {
        log.info( msg, t );
    }
    /** Logs a message with priority ERROR
     * @param msg Message
     */
    public  void    error( String msg ) {
        log.error( msg );
    }
    /** Logs a message and an exception with priority ERROR
     * @param msg Message
     * @param t Exception
     */
    public  void    error( String msg, Throwable t  ) {
        log.error( msg, t );
    }

} //BaseAdminCommand
