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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import java.util.Arrays;

/** Exists in EJBCA due to MarshalledValue not existing in JBoss 7 and higher. 
 * This can give upgrade issues from old version of EJBCA (4) to EJBCA 6, 
 * moving directly from JBoss 5 to JBoss 7.
 * See: https://sourceforge.net/p/ejbca/discussion/123123/thread/e88b1c50/?limit=25
 * Jira: https://jira.primekey.se/browse/ECA-3687
 * All these classes can be removed when we do not support upgrades from EJBCA 4 any longer.
 */

/**
 * A simple replacement for the RMI MarshalledObject that uses the thread
 * context class loader for resolving classes and proxies. This currently does
 * not support class annotations and dynamic class loading.
 *
 * @author Scott.Stark@jboss.org
 * @version $Revision: 81179 $
 */
public class MarshalledValue
   implements java.io.Externalizable
{
   /** Serial Version Identifier. */
   private static final long serialVersionUID = -1527598981234110311L;

   /**
    * The serialized form of the value. If <code>serializedForm</code> is
    * <code>null</code> then the object marshalled was a <code>null</code>
    * reference.
    */
   private byte[] serializedForm;

   /**
    * The RMI MarshalledObject hash of the serializedForm array
    */
   private int hashCode;

   /**
    * Exposed for externalization.
    */
   public MarshalledValue()
   {
      super();
   }

   public MarshalledValue(Object obj) throws IOException
   {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      MarshalledValueOutputStream mvos = new MarshalledValueOutputStream(baos);
      mvos.writeObject(obj);
      mvos.flush();
      serializedForm = baos.toByteArray();
      mvos.close();
      // Use the java.rmi.MarshalledObject hash code calculation
      int hash = 0;
      for (int i = 0; i < serializedForm.length; i++)
      {
         hash = 31 * hash + serializedForm[i];
      }

      hashCode = hash;
   }

   public Object get() throws IOException, ClassNotFoundException
   {
      if (serializedForm == null)
         return null;

      ByteArrayInputStream bais = new ByteArrayInputStream(serializedForm);
      MarshalledValueInputStream mvis = new MarshalledValueInputStream(bais);
      Object retValue =  mvis.readObject();
      mvis.close();
      return retValue;
   }

   public byte[] toByteArray()
   {
      return serializedForm;
   }

   public int size()
   {
      int size = serializedForm != null ? serializedForm.length : 0;
      return size;
   }

   /**
    * Return a hash code for the serialized form of the value.
    *
    * @return the serialized form value hash.
    */
   public int hashCode()
   {
      return hashCode;
   }

   public boolean equals(Object obj)
   {
      if( this == obj )
         return true;

      boolean equals = false;
      if( obj instanceof MarshalledValue )
      {
         MarshalledValue mv = (MarshalledValue) obj;
         if( serializedForm == mv.serializedForm )
         {
            equals = true;
         }
         else
         {
            equals = Arrays.equals(serializedForm, mv.serializedForm);
         }
      }
      return equals;
   }

   /**
    * The object implements the readExternal method to restore its
    * contents by calling the methods of DataInput for primitive
    * types and readObject for objects, strings and arrays.  The
    * readExternal method must read the values in the same sequence
    * and with the same types as were written by writeExternal.
    *
    * @param in the stream to read data from in order to restore the object
    *
    * @throws IOException              if I/O errors occur
    * @throws ClassNotFoundException   If the class for an object being
    *                                  restored cannot be found.
    */
   public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException
   {
      int length = in.readInt();
      serializedForm = null;
      if( length > 0 )
      {
         serializedForm = new byte[length];
         in.readFully(serializedForm);
      }
      hashCode = in.readInt();
   }

   /**
    * The object implements the writeExternal method to save its contents
    * by calling the methods of DataOutput for its primitive values or
    * calling the writeObject method of ObjectOutput for objects, strings,
    * and arrays.
    *
    * @serialData Overriding methods should use this tag to describe
    *            the data layout of this Externalizable object.
    *            List the sequence of element types and, if possible,
    *            relate the element to a public/protected field and/or
    *            method of this Externalizable class.
    *
    * @param out    the stream to write the object to
    *
    * @throws IOException   Includes any I/O exceptions that may occur
    */
   public void writeExternal(ObjectOutput out) throws IOException
   {
      int length = serializedForm != null ? serializedForm.length : 0;
      out.writeInt(length);
      if( length > 0 )
      {
         out.write(serializedForm);
      }
      out.writeInt(hashCode);
   }
}
