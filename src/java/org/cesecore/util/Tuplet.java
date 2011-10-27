/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import java.io.Serializable;

/**
 * Trivial template implementation of a tuplet.
 * 
 * Based on Tuplet.java 245 2011-02-09 19:28:08Z filiper from cesecore.
 * 
 * @version $Id$
 *
 */
public final class Tuplet<K, V> implements Serializable{

    private static final long serialVersionUID = -3272995902610306280L;
    private final K firstElement;
    private final V secondElement;
    
    public Tuplet(K firstElement, V secondElement) {
        this.firstElement = firstElement;
        this.secondElement = secondElement;
    }
    
    public K getFirstElement() {
        return firstElement;
    }
    
    public V getSecondElement() {
        return secondElement;
    }

    @Override
    public int hashCode() {
        final int prime = 1337;
        int result = 1;
        result = prime * result + ((firstElement == null) ? 0 : firstElement.hashCode());
        result = prime * result + ((secondElement == null) ? 0 : secondElement.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        Tuplet<?, ?> other = (Tuplet<?, ?>) obj;
        if (firstElement == null) {
            if (other.firstElement != null) {
                return false;
            }
        } else if (!firstElement.equals(other.firstElement)) {
            return false;
        }
        if (secondElement == null) {
            if (other.secondElement != null) {
                return false;
            }
        } else if (!secondElement.equals(other.secondElement)) {
            return false;
        }
        return true;
    }
    
}
