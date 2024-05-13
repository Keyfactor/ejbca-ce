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
 
 
package org.cesecore.audit.enums;

import java.io.Serializable;

/**
 *  Generic constant type holder.
 * 
 * @version $Id$
 * 
 */
public interface ConstantType<T extends ConstantType<T>> extends Serializable {
    boolean equals(final T value);
}
