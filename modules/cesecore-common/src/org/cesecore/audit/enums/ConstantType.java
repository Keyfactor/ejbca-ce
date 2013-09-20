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
    String toString();
}
