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
package org.cesecore;

import java.io.Serializable;

/**
 * A Class implements the NonSensitiveCloneable interface to indicate that can clone itself into non-sensitive clone.
 * Intended to be used with EJBCA exceptions that might carry information leak over peers.
 * @version $Id$
 *
 */
public interface NonSensitiveCloneable extends Serializable{

    NonSensitiveCloneable getNonSensitiveClone();
}
