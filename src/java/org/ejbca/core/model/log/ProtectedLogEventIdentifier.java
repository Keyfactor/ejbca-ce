/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.log;

import java.io.Serializable;
import java.nio.ByteBuffer;

import org.ejbca.util.Base64;

/**
 * (NodeGUID, counter) identifer for ProtectedLogEvent
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogEventIdentifier implements Serializable{
	
	private Integer nodeGUID;
	private Long counter;
	
	public ProtectedLogEventIdentifier(int nodeGUID, long counter) {
		this.nodeGUID = nodeGUID;
		this.counter = counter;
	}
	
	public ProtectedLogEventIdentifier(String base64EncodedString) {
		setAsBase64EncodedString(base64EncodedString);
	}

	public ProtectedLogEventIdentifier(byte[] asByteArray) {
		if (asByteArray == null) {
			nodeGUID = null;
			counter = null;
		} else {
			setAsByteArray(asByteArray);
		}
	}

	/**
	 * @return true if the nodeGUID and counter are equal for the two objects.
	 */
	public boolean equals(ProtectedLogEventIdentifier protectedLogEventIdentifier) {
		return nodeGUID.intValue() == protectedLogEventIdentifier.getNodeGUID() && counter.longValue() == protectedLogEventIdentifier.getCounter();
	}
	
	public int getNodeGUID() {
		return nodeGUID;
	}
	
	public long getCounter() {
		return counter;
	}
	
	static public int getByteArraySize() {
		return 4+8;
	}
	
	public byte[] getAsByteArray() {
		if (nodeGUID == null || counter == null) {
			return null;
		} else {
			ByteBuffer bb = ByteBuffer.allocate(getByteArraySize());
			return bb.putInt(nodeGUID).putLong(counter).array();
		}
	}

	private void setAsByteArray(byte[] data) {
		if (data == null) {
			nodeGUID = null;
			counter = null;
		} else {
			ByteBuffer bb = ByteBuffer.allocate(getByteArraySize()*3);
			bb.put(data);
			bb.rewind();
			nodeGUID = bb.getInt();
			counter = bb.getLong();
		}
	}
	
	public String getAsBase64EncodedString() {
		byte[] data = getAsByteArray();
		if (data != null) {
			return new String(Base64.encode(data));
		} else {
			return null;
		}
	}

	private void setAsBase64EncodedString(String data) {
		if (data == null) {
			nodeGUID = null;
			counter = null;
		} else {
			setAsByteArray(Base64.decode(data.getBytes()));
		}
	}
	
	public int hashCode() {
		return getNodeGUID() + new Long(getCounter()).intValue();
	}
}
