package se.anatom.ejbca.ra;


/**
 * Implementations of this interface creates RMI objects to be used as an
 * alternative way to access ejbca.
 *
 * @version $Id: RMIFactory.java,v 1.5 2003-01-12 17:16:28 anatom Exp $
 */
public interface RMIFactory {

    /**
     * executes code that may be used to set up a RMI server.
     *
     */
    void startConnection( String[] args ) throws Exception;
}
