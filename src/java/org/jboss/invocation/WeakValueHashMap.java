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

import java.lang.ref.ReferenceQueue;
import java.util.Map;

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
public class WeakValueHashMap<K, V> extends ReferenceValueHashMap<K, V>
{
   /**
    * Constructs a new, empty <code>WeakValueHashMap</code> with the given
    * initial capacity and the given load factor.
    *
    * @param  initialCapacity  The initial capacity of the
    *                          <code>WeakValueHashMap</code>
    *
    * @param  loadFactor       The load factor of the <code>WeakValueHashMap</code>
    *
    * @throws IllegalArgumentException  If the initial capacity is less than
    *                                   zero, or if the load factor is
    *                                   nonpositive
    */
   public WeakValueHashMap(int initialCapacity, float loadFactor)
   {
      super(initialCapacity, loadFactor);
   }

   /**
    * Constructs a new, empty <code>WeakValueHashMap</code> with the given
    * initial capacity and the default load factor, which is
    * <code>0.75</code>.
    *
    * @param  initialCapacity  The initial capacity of the
    *                          <code>WeakValueHashMap</code>
    *
    * @throws IllegalArgumentException  If the initial capacity is less than
    *                                   zero
    */
   public WeakValueHashMap(int initialCapacity)
   {
      super(initialCapacity);
   }

   /**
    * Constructs a new, empty <code>WeakValueHashMap</code> with the default
    * initial capacity and the default load factor, which is
    * <code>0.75</code>.
    */
   public WeakValueHashMap()
   {
   }

   /**
    * Constructs a new <code>WeakValueHashMap</code> with the same mappings as the
    * specified <tt>Map</tt>.  The <code>WeakValueHashMap</code> is created with an
    * initial capacity of twice the number of mappings in the specified map
    * or 11 (whichever is greater), and a default load factor, which is
    * <tt>0.75</tt>.
    *
    * @param   t the map whose mappings are to be placed in this map.
    * @since    1.3
    */
   public WeakValueHashMap(Map<K, V> t)
   {
      super(t);
   }

   protected ValueRef<K, V> create(K key, V value, ReferenceQueue<V> q)
   {
      return WeakValueRef.create(key, value, q);
   }
}
