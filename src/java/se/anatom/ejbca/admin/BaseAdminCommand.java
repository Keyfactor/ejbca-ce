
package se.anatom.ejbca.admin;

import javax.naming.*;

import org.apache.log4j.*;

/** Base for all AdminCommands, contains functions for getting initial context and logging
 *
 * @version $Id: BaseAdminCommand.java,v 1.4 2002-04-14 08:49:31 anatom Exp $
 */
public abstract class BaseAdminCommand implements IAdminCommand {

    /** Log4j instance for Base */
    private static Category baseCat = Category.getInstance( BaseAdminCommand.class.getName() );
    /** Log4j instance for actual class */
    private Category cat;
    
    /** Cached initial context to save JNDI lookups */
    private static InitialContext cacheCtx = null;
    
    /** holder of argument array */
    protected String[] args = null;
    
    /** Creates a new instance of BaseAdminCommand */
    public BaseAdminCommand(String[] args) {
        cat = Category.getInstance( this.getClass().getName() );
        this.args = args;
    }

    /** Gets InitialContext
     *@return InitialContext
     */
    protected InitialContext getInitialContext() throws NamingException {
        baseCat.debug(">getInitialContext()");
        try {
            if( cacheCtx == null )
                cacheCtx = new InitialContext();
            baseCat.debug("<getInitialContext()");
            return  cacheCtx;
        } catch (NamingException e ) {
            baseCat.error("Can't get InitialContext", e);
            throw e;
        }
    } // getInitialContext
    
    /** Logs a message with priority DEBUG
     * @param msg Message
     */
    public  void    debug( String msg ) {
        cat.debug( msg );
    }
    /** Logs a message and an exception with priority DEBUG
     * @param msg Message
     * @param t Exception
     */
    public  void    debug( String msg, Throwable t ) {
        cat.debug( msg, t );
    }
    /** Logs a message with priority INFO
     * @param msg Message
     */
    public  void    info( String msg ) {
        cat.info( msg );
    }
    /** Logs a message and an exception with priority INFO
     * @param msg Message
     * @param t Exception
     */
    public  void    info( String msg, Throwable t  ) {
        cat.info( msg, t );
    }
    /** Logs a message with priority ERROR
     * @param msg Message
     */
    public  void    error( String msg ) {
        cat.error( msg );
    }    
    /** Logs a message and an exception with priority ERROR
     * @param msg Message
     * @param t Exception
     */
    public  void    error( String msg, Throwable t  ) {
        cat.error( msg, t );
    }
    
} //BaseAdminCommand
