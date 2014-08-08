/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
  * by the @authors tag. See the copyright.txt in the distribution for a
  * full listing of individual contributors.
  *
  * This is free software; you can redistribute it and/or modify it
  * under the terms of the GNU Lesser General Public License as
  * published by the Free Software Foundation; either version 2.1 of
  * the License, or (at your option) any later version.
  *
  * This software is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this software; if not, write to the Free
  * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
  * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
  */
package org.jboss.invocation;

import java.util.Map;
import java.util.HashMap;
import java.util.Comparator;
import java.util.SortedMap;

/** Exists in EJBCA due to MarshalledValue not existing in JBoss 7 and higher. 
 * This can give upgrade issues from old version of EJBCA (4) to EJBCA 6, 
 * moving directly from JBoss 5 to JBoss 7.
 * See: https://sourceforge.net/p/ejbca/discussion/123123/thread/e88b1c50/?limit=25
 * Jira: https://jira.primekey.se/browse/ECA-3687
 * All these classes can be removed when we do not support upgrades from EJBCA 4 any longer.
 */

/**
 * This Map will remove entries when the value in the map has been
 * cleaned from garbage collection
 *
 * @param <K> the key type
 * @param <V> the value type
 * @author  <a href="mailto:bill@jboss.org">Bill Burke</a>
 * @author  <a href="mailto:adrian@jboss.org">Adrian Brock</a>
 * @author  <a href="mailto:ales.justin@jboss.org">Ales Justin</a>
 */
public abstract class ReferenceValueHashMap<K, V> extends ReferenceValueMap<K, V>
{
   protected ReferenceValueHashMap()
   {
   }

   protected ReferenceValueHashMap(int initialCapacity)
   {
      super(initialCapacity);
   }

   protected ReferenceValueHashMap(int initialCapacity, float loadFactor)
   {
      super(initialCapacity, loadFactor);
   }

   protected ReferenceValueHashMap(Map<K, V> t)
   {
      super(t);
   }

   protected Map<K, ValueRef<K, V>> createMap(int initialCapacity, float loadFactor)
   {
      return new HashMap<K, ValueRef<K,V>>(initialCapacity, loadFactor);
   }

   protected Map<K, ValueRef<K, V>> createMap(int initialCapacity)
   {
      return new HashMap<K, ValueRef<K,V>>(initialCapacity);
   }

   protected Map<K, ValueRef<K, V>> createMap()
   {
      return new HashMap<K, ValueRef<K,V>>();
   }

   protected Map<K, ValueRef<K, V>> createMap(Comparator<K> kComparator)
   {
      throw new UnsupportedOperationException("Cannot create HashMap with such parameters.");
   }

   protected Map<K, ValueRef<K, V>> createMap(SortedMap<K, ValueRef<K, V>> kValueRefSortedMap)
   {
      throw new UnsupportedOperationException("Cannot create HashMap with such parameters.");
   }
}