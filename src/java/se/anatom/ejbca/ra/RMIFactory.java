package se.anatom.ejbca.ra;

import se.anatom.ejbca.ca.sign.ISignSessionRemote;

/**
 * Implementations of this interface creates RMI objects to be used as an
 * alternative way to access ejbca.
 *
 * @version $Id: RMIFactory.java,v 1.4 2002-09-19 08:30:01 primelars Exp $
 */
public interface RMIFactory {


    /**
     * executes code that may be used to set up a RMI server.
     *
     */
    void startConnection( String[] args ) throws Exception;
}
