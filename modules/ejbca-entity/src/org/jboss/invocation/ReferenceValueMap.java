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
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
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
public abstract class ReferenceValueMap<K, V> extends AbstractMap<K, V>
{
   /** Hash table mapping keys to ref values */
   private Map<K, ValueRef<K, V>> map;

   /** Reference queue for cleared RefKeys */
   private ReferenceQueue<V> queue = new ReferenceQueue<V>();

   protected ReferenceValueMap()
   {
      map = createMap();
   }

   protected ReferenceValueMap(int initialCapacity)
   {
      map = createMap(initialCapacity);
   }

   protected ReferenceValueMap(int initialCapacity, float loadFactor)
   {
      map = createMap(initialCapacity, loadFactor);
   }

   protected ReferenceValueMap(Map<K, V> t)
   {
      this(Math.max(2*t.size(), 11), 0.75f);
      putAll(t);
   }

   protected ReferenceValueMap(Comparator<K> comparator)
   {
      map = createMap(comparator);
   }

   protected ReferenceValueMap(SortedMap<K, ValueRef<K, V>> sorted)
   {
      map = createMap(sorted);
   }
   
   /**
    * Create map.
    *
    * @return new map instance
    */
   protected abstract Map<K, ValueRef<K, V>> createMap();

   /**
    * Create map.
    *
    * @param initialCapacity the initial capacity
    * @return new map instance
    */
   protected abstract Map<K, ValueRef<K, V>> createMap(int initialCapacity);

   /**
    * Create map.
    *
    * @param initialCapacity the initial capacity
    * @param loadFactor the load factor
    * @return new map instance
    */
   protected abstract Map<K, ValueRef<K, V>> createMap(int initialCapacity, float loadFactor);

   /**
    * Create map.
    *
    * @param comparator the comparator
    * @return new map instance
    */
   protected abstract Map<K, ValueRef<K, V>> createMap(Comparator<K> comparator);

   /**
    * Create map.
    *
    * @param map the sorted map
    * @return new map instance
    */
   protected abstract Map<K, ValueRef<K, V>> createMap(SortedMap<K, ValueRef<K, V>> map);

   @Override
   public int size()
   {
      processQueue();
      return map.size();
   }

   @Override
   public boolean containsKey(Object key)
   {
      processQueue();
      return map.containsKey(key);
   }

   @Override
   public V get(Object key)
   {
      processQueue();
      ValueRef<K, V> ref = map.get(key);
      if (ref != null)
         return ref.get();
      return null;
   }

   @Override
   public V put(K key, V value)
   {
      processQueue();
      ValueRef<K, V> ref = create(key, value, queue);
      ValueRef<K, V> result = map.put(key, ref);
      if (result != null)
         return result.get();
      return null;
   }

   @Override
   public V remove(Object key)
   {
      processQueue();
      ValueRef<K, V> result = map.remove(key);
      if (result != null)
         return result.get();
      return null;
   }

   @Override
   public Set<Entry<K,V>> entrySet()
   {
      processQueue();
      return new EntrySet();
   }

   @Override
   public void clear()
   {
      processQueue();
      map.clear();
   }

   /**
    * Remove all entries whose values have been discarded.
    */
   @SuppressWarnings("unchecked")
   private void processQueue()
   {
      ValueRef<K, V> ref = (ValueRef<K, V>) queue.poll();
      while (ref != null)
      {
         // only remove if it is the *exact* same WeakValueRef
         if (ref == map.get(ref.getKey()))
            map.remove(ref.getKey());

         ref = (ValueRef<K, V>) queue.poll();
      }
   }

   /**
    * EntrySet.
    */
   private class EntrySet extends AbstractSet<Entry<K, V>>
   {
      @Override
      public Iterator<Entry<K, V>> iterator()
      {
         return new EntrySetIterator(map.entrySet().iterator());
      }

      @Override
      public int size()
      {
         return ReferenceValueMap.this.size();
      }
   }

   /**
    * EntrySet iterator
    */
   private class EntrySetIterator implements Iterator<Entry<K, V>>
   {
      /** The delegate */
      private Iterator<Entry<K, ValueRef<K, V>>> delegate;

      /**
       * Create a new EntrySetIterator.
       *
       * @param delegate the delegate
       */
      public EntrySetIterator(Iterator<Entry<K, ValueRef<K, V>>> delegate)
      {
         this.delegate = delegate;
      }

      public boolean hasNext()
      {
         return delegate.hasNext();
      }

      public Entry<K, V> next()
      {
         Entry<K, ValueRef<K, V>> next = delegate.next();
         return next.getValue();
      }

      public void remove()
      {
         throw new UnsupportedOperationException("remove");
      }
   }

   /**
    * Create new value ref instance.
    *
    * @param key the key
    * @param value the value
    * @param q the ref queue
    * @return new value ref instance
    */
   protected abstract ValueRef<K, V> create(K key, V value, ReferenceQueue<V> q);

   @Override
   public String toString()
   {
      return map.toString();
   }
}