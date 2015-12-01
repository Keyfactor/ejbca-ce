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
import java.io.OutputStream;
import java.io.ObjectOutputStream;
import java.rmi.Remote;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteStub;
import java.security.PrivilegedAction;
import java.security.AccessController;

/** Exists in EJBCA due to MarshalledValue not existing in JBoss 7 and higher. 
 * This can give upgrade issues from old version of EJBCA (4) to EJBCA 6, 
 * moving directly from JBoss 5 to JBoss 7.
 * See: https://sourceforge.net/p/ejbca/discussion/123123/thread/e88b1c50/?limit=25
 * Jira: https://jira.primekey.se/browse/ECA-3687
 * All these classes can be removed when we do not support upgrades from EJBCA 4 any longer.
 */

/**
 * An ObjectOutputStream subclass used by the MarshalledValue class to
 * ensure the classes and proxies are loaded using the thread context
 * class loader. Currently this does not do anything as neither class or
 * proxy annotations are used.
 *
 * @author Scott.Stark@jboss.org
 * @version $Revision: 81030 $
 */
public class MarshalledValueOutputStream
   extends ObjectOutputStream
{
   /** Creates a new instance of MarshalledValueOutputStream
    If there is a security manager installed, this method requires a
    SerializablePermission("enableSubstitution") permission to ensure it's
    ok to enable the stream to do replacement of objects in the stream.
    */
   public MarshalledValueOutputStream(OutputStream os) throws IOException
   {
      super(os);
      EnableReplaceObjectAction.enableReplaceObject(this);
   }

   /**
    * @throws IOException   Any exception thrown by the underlying OutputStream.
    */
   protected void annotateClass(@SuppressWarnings("rawtypes") Class cl) throws IOException
   {
      super.annotateClass(cl);
   }
   
   /**
    * @throws IOException   Any exception thrown by the underlying OutputStream.
    */
   protected void annotateProxyClass(@SuppressWarnings("rawtypes") Class cl) throws IOException
   {
      super.annotateProxyClass(cl);
   }

   /** Override replaceObject to check for Remote objects that are
    not RemoteStubs.
   */
   protected Object replaceObject(Object obj) throws IOException
   {
      if( (obj instanceof Remote) && !(obj instanceof RemoteStub) )
      {
         Remote remote = (Remote) obj;
         try
         {
            obj = RemoteObject.toStub(remote);
         }
         catch(IOException ignore)
         {
            // Let the Serialization layer try with the orignal obj
         }
      }
      return obj;
   }

   @SuppressWarnings("rawtypes")
   private static class EnableReplaceObjectAction implements PrivilegedAction
   {
      MarshalledValueOutputStream os;
      EnableReplaceObjectAction(MarshalledValueOutputStream os)
      {
         this.os = os;
      }
      public Object run()
      {
         os.enableReplaceObject(true);
         return null;
      }
      @SuppressWarnings("unchecked")
    static void enableReplaceObject(MarshalledValueOutputStream os)
      {
         EnableReplaceObjectAction action = new EnableReplaceObjectAction(os);
         AccessController.doPrivileged(action);
      }
   }
}
