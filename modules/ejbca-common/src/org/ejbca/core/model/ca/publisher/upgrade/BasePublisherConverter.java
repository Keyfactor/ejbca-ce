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
package org.ejbca.core.model.ca.publisher.upgrade;

import org.ejbca.core.model.ca.publisher.BasePublisher;

/**
 * Interface to allow instantiation of Publishers from outside the local context.
 * 
 * @version $Id$
 *
 */
public interface BasePublisherConverter {
    
    /**
     * Creates a publisher based on the given BasePublisher
     * 
     * @param BasePublisher a BasePublisher to convert from
     * @return a {@link BasePublisher} from the given publisher, or null if publisher was not viable. 
     */
    BasePublisher createPublisher(final BasePublisher publisher);

}
