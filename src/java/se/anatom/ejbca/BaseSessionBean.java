
package se.anatom.ejbca;

import javax.ejb.CreateException;
import javax.ejb.SessionBean;
import javax.ejb.SessionContext;
import javax.ejb.EJBException;
import javax.naming.*;
import javax.rmi.PortableRemoteObject;

import org.apache.log4j.*;


/** Base for Session Beans providing common features, new Session Beans 'extends' BaseSessionBean.
 *
 * @version $Id: BaseSessionBean.java,v 1.1.1.1 2001-11-15 14:58:13 anatom Exp $
 */
public class BaseSessionBean implements SessionBean {
    
    /** Log4j instance for Base */
    private static Category baseCat = Category.getInstance( BaseSessionBean.class.getName() );
    /** Log4j instance for actual class */
    public  Category    cat;
    
    private SessionContext  ctx;
    /** Cached initial context to save JNDI lookups */
    InitialContext cacheCtx = null;
    
    /** Initializes logging mechanism per instance */
    public BaseSessionBean() {
        cat = Category.getInstance( this.getClass().getName() );
    }
    
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
    
    /** Logs a message with priority WARN
     * @param msg Message
     */
    public  void    warn( String msg ) {
        cat.warn( msg );
    }
    
    /** Logs a message and an exception with priority WARN
     * @param msg Message
     * @param t Exception
     */
    public  void    warn( String msg, Throwable t  ) {
        cat.warn( msg, t );
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
    
    /** Gets InitialContext
     *@return InitialContext
     */
    public InitialContext getInitialContext() {
        baseCat.debug(">getInitialContext()");
        try {
            if( cacheCtx == null )
                cacheCtx = new InitialContext();
            baseCat.debug("<getInitialContext()");
            return  cacheCtx;
        } catch (NamingException e ) {
            baseCat.error("Can't get InitialContext", e);
            throw new EJBException( e );
        }
    }
    
    /** Looks up a JNDI name using the (cached) InitialContext
     *@param jndiName the JNDI name to lookup.
     *@param type the class type to narrow the object to.
     *@return Object that can be casted to 'type'.
     */
    public Object lookup( String jndiName, Class type ) {
        baseCat.debug(">lookup("+jndiName+")");
        InitialContext ctx = getInitialContext();
        try {
            Object ret = PortableRemoteObject.narrow( ctx.lookup( jndiName ), type );
            baseCat.debug("<lookup("+jndiName+")");
            return ret;
        } catch( NamingException e ) {
            baseCat.error("Can't lookup '"+jndiName+"'", e);
            throw new EJBException( e );
        }
        
    }
    
    public void ejbActivate() throws javax.ejb.EJBException, java.rmi.RemoteException {
    }
    
    public void ejbRemove() throws javax.ejb.EJBException, java.rmi.RemoteException {
    }
    
    public void ejbPassivate() throws javax.ejb.EJBException, java.rmi.RemoteException {
    }
    
    public void setSessionContext(final javax.ejb.SessionContext ctx ) throws javax.ejb.EJBException,
    java.rmi.RemoteException {
        this.ctx = ctx;
    }
    
    public SessionContext getSessionContext() {
        return  ctx;
    }
}

