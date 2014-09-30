/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.services;

import java.io.Serializable;

/**
 * General Class used to send information from a worker to a action.
 * 
 * Can contain any data that both the worker and action supports.
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */
public interface ActionInfo extends Serializable {

}
