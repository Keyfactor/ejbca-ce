/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
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

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Proxy;

import org.apache.log4j.Logger;

/** Exists in EJBCA due to MarshalledValue not existing in JBoss 7 and higher. 
 * This can give upgrade issues from old version of EJBCA (4) to EJBCA 6, 
 * moving directly from JBoss 5 to JBoss 7.
 * See: https://sourceforge.net/p/ejbca/discussion/123123/thread/e88b1c50/?limit=25
 * Jira: https://jira.primekey.se/browse/ECA-3687
 * All these classes can be removed when we do not support upgrades from EJBCA 4 any longer.
 */

/**
 * An ObjectInputStream subclass used by the MarshalledValue class to
 * ensure the classes and proxies are loaded using the thread context
 * class loader.
 *
 * @author Scott.Stark@jboss.org
 * @version $Revision: 81030 $
 */
public class MarshalledValueInputStream
   extends ObjectInputStream
{
   private static Logger log = Logger.getLogger(MarshalledValueInputStream.class);
   /** A class wide cache of proxy classes populated by resolveProxyClass */
   private static WeakValueHashMap classCache;

   /** Enable local caching of resolved proxy classes. This can only be used
    * if there is a single ULR and no redeployment of the proxy classes.
    *
    * @param flag true to enable caching, false to disable it
    */
   public static void useClassCache(boolean flag)
   {
      if( flag == true )
         classCache = new WeakValueHashMap();
      else
         classCache = null;
   }

   /** Clear the current proxy cache.
    *
    */
   public static void flushClassCache()
   {
      classCache.clear();
   }

   /**
    * Creates a new instance of MarshalledValueOutputStream
    */
   public MarshalledValueInputStream(InputStream is) throws IOException
   {
      super(is);
   }

   /**
    * Use the thread context class loader to resolve the class
    *
    * @throws IOException   Any exception thrown by the underlying OutputStream.
    */
   protected Class resolveClass(ObjectStreamClass v)
      throws IOException, ClassNotFoundException
   {
      String className = v.getName();
      Class resolvedClass = null;
      // Check the class cache first if it exists
      if( classCache != null )
      {
         synchronized( classCache )
         {
            resolvedClass = (Class) classCache.get(className);
         }
      }

      if( resolvedClass == null )
      {
         ClassLoader loader = SecurityActions.getContextClassLoader();
         try
         {
            resolvedClass = loader.loadClass(className);
         }
         catch(ClassNotFoundException e)
         {
            /* Use the super.resolveClass() call which will resolve array
            classes and primitives. We do not use this by default as this can
            result in caching of stale values across redeployments.
            */            
            resolvedClass = super.resolveClass(v);
         }
         if( classCache != null )
         {
            synchronized( classCache )
            {
               classCache.put(className, resolvedClass);
            }
         }
      }
      return resolvedClass;
   }

   protected Class resolveProxyClass(String[] interfaces)
      throws IOException, ClassNotFoundException
   {
      if( log.isTraceEnabled() )
      {
         StringBuffer tmp = new StringBuffer("[");
         for(int i = 0; i < interfaces.length; i ++)
         {
            if( i > 0 )
               tmp.append(',');
            tmp.append(interfaces[i]);
         }
         tmp.append(']');
         log.trace("resolveProxyClass called, ifaces="+tmp.toString());
      }

      // Load the interfaces from the cache or thread context class loader
      ClassLoader loader = null;
      Class[] ifaceClasses = new Class[interfaces.length];
      for (int i = 0; i < interfaces.length; i++)
      {
         Class iface = null;
         String className = interfaces[i];
         // Check the proxy cache if it exists
         if( classCache != null )
         {
            synchronized( classCache )
            {
               iface = (Class) classCache.get(className);
            }
         }

         // Load the interface class using the thread context ClassLoader
         if( iface == null )
         {
            if( loader == null )
               loader = Thread.currentThread().getContextClassLoader();
            iface = loader.loadClass(className);
            if( classCache != null )
            {
               synchronized( classCache )
               {
                  classCache.put(className, iface);
               }
            }
         }
         ifaceClasses[i] = iface;
      }

      return Proxy.getProxyClass(loader, ifaceClasses);
   }
}
