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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/** Can be used as Filter InputStream to prevent StringBuilder heap overflow during deserialization. 
 * 
 * Simple usage:
 * ObjectInputStream objectInputStream = new ObjectInputStream(new SecurityFilterInputStream(new ByteArrayInputStream(someByteArray), 256));
 * objectInputStream.readObject(); //If serialized object have more than 256 bytes, SecurityException will be thrown
 * 
 * @see SecurityFilterInputStreamTest for more examples
 * 
 * @version $Id$
 */
public class SecurityFilterInputStream extends FilterInputStream{

    private long len = 0;
    private long maxBytes = DEFAULT_MAX_BYTES;
    
    public static final long DEFAULT_MAX_BYTES = 0xFFFFF;
    
    public SecurityFilterInputStream(InputStream inputStream){
        super(inputStream);
    }
    
    public SecurityFilterInputStream(InputStream inputStream, long maxBytes){
        super(inputStream);
        this.maxBytes = maxBytes;
    }
    
    @Override
    public int read() throws IOException {
        int val = super.read();
        if (val != -1) {
            len++;
            checkLength();
        }
        return val;
    }
    
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int val = super.read(b, off, len);
        if (val > 0) {
            this.len += val;
            checkLength();
        }
        return val;
    }
    
    
    private void checkLength() throws IOException {
        if (len > maxBytes) {
            throw new SecurityException("Security violation: attempt to deserialize too many bytes from stream. Limit is " + maxBytes);
        }
    }

    /**
     * Returns max bytes that can be read from serialized object.
     * @param 
     *      max bytes that can be read from serialized object. Default: 0xFFFFF 
     */
    public long getMaxBytes() {
        return maxBytes;
    }

    /**
     * Set max bytes that can be read from serialized object
     * @return 
     *      max bytes that can be read from serialized object.
     */
    public void setMaxBytes(long maxBytes) {
        this.maxBytes = maxBytes;
    }
    
    
}
