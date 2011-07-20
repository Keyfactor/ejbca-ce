package org.cesecore.audit.enums;

import java.io.Serializable;

/**
 *  Generic constant type holder.
 * 
 * Based on CESeCore version:
 *      ConstantType.java 920 2011-07-01 11:27:04Z filiper
 * 
 * @version $Id$
 * 
 */
public interface ConstantType<T extends ConstantType<T>> extends Serializable {
    boolean equals(final T value);
    String toString();
}
