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
 
package se.anatom.ejbca;


import javax.ejb.CreateException;
import javax.ejb.EJBLocalHome;


/**
 * Local Home interface for JobRunner session.
 *
 * @version $Id: IJobRunnerSessionLocalHome.java,v 1.2 2004-04-16 07:39:01 anatom Exp $
 */
public interface IJobRunnerSessionLocalHome extends EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IJobRunnerSessionRemote interface
     *
     * @throws CreateException 
     */
    IJobRunnerSessionLocal create() throws CreateException;
}
