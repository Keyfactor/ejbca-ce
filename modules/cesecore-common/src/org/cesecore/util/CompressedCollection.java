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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

import org.apache.log4j.Logger;

/**
 * Special Collection that compresses all the added objects to a in memory byte array.
 * 
 * Objects are read from the collection by using a iterator over a decompression InputStream.
 * To avoid memory leaks, the .clear() call should be used when the collection is no longer needed.
 * 
 * The implementation is not thread safe.
 * 
 * Example use-case: a RevokedCertInfo takes 248 bytes in serialized form, but averages at only 48
 * bytes in compressed serialized form.
 * 
 * @version $Id$
 */
public class CompressedCollection<T extends Serializable> implements Collection<T> , Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CompressedCollection.class);

    private ByteArrayOutputStream baos = null;
    private ObjectOutputStream oos = null;
    private byte[] compressedData = null;
    private int size = 0;
    private final List<ObjectInputStream> oiss = new ArrayList<ObjectInputStream>();

    public CompressedCollection() {
        clear();
    }
    
    @Override
    public boolean add(final T object) {
        if (compressedData!=null) {
            throw new IllegalStateException("closeForWrite() has alread been called without clear() for this CompressedCollection.");
        }
        boolean ret = false;
        if (object!=null) {
            try {
                getObjectOutputStream().writeObject(object);
                ret = true;
                size++;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return ret;
    }

    /** Lazy initialization of our in memory object storage */
    private ObjectOutputStream getObjectOutputStream() throws IOException {
        if (oos==null) {
            baos = new ByteArrayOutputStream();
            final DeflaterOutputStream dos = new DeflaterOutputStream(baos, new Deflater(Deflater.BEST_COMPRESSION));
            oos = new ObjectOutputStream(dos);
        }
        return oos;
    }

    @Override
    public boolean addAll(final Collection<? extends T> objects) {
        for (final T object : objects) {
            add(object);
        }
        return objects.size()!=0;
    }

    @Override
    public void clear() {
        if (oos!=null) {
            // Clean up OutputStream, unless this has already been done
            try {
                oos.close();
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
            oos = null;
        }
        size = 0;
        compressedData = null;
        // Clean up all InputStreams, unless this has already been done
        for (final ObjectInputStream ois : oiss) {
            try {
                ois.close();
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
        }
        oiss.clear();
    }

    @Override
    public boolean contains(Object object) {
        final Iterator<T> iterator = iterator();
        while (iterator.hasNext()) {
            final T t = iterator.next();
            if (t.equals(object)) {
                try {
                    oiss.get(oiss.size()-1).close();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                oiss.remove(oiss.size()-1);
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean containsAll(final Collection<?> objects) {
        throw new UnsupportedOperationException();  // This is not really an optional operation for a Collection
    }

    @Override
    public boolean isEmpty() {
        return size==0;
    }

    /** Signal that no more data will be added to this collection. Call before Serialization. */
    public void closeForWrite() {
        if (compressedData==null) {
            if (oos==null) {
                // Nothing was added
                compressedData = new byte[0];
            } else {
                // Clean up outputstream now when we are about to read the data
                try {
                    oos.flush();
                    oos.close();
                    oos = null;
                    compressedData = baos.toByteArray();
                    baos = null;
                    if (log.isDebugEnabled()) {
                        log.debug("Compressed data of " + size + " entries to " + compressedData.length + " bytes.");
                    }
                } catch (IOException e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
    }

    @Override
    public Iterator<T> iterator() {
        closeForWrite();
        // Create a new decompression stream over the data that belongs to the Iterator
        final ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
        final InflaterInputStream iis = new InflaterInputStream(bais);
        final ObjectInputStream ois;
        if (compressedData.length==0) {
            ois = null;
        } else {
            try {
                ois = new ObjectInputStream(iis);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            oiss.add(ois);
        }
        return new Iterator<T>() {
            private T next = null;
            
            @Override
            public boolean hasNext() {
                try {
                    next = readNext();
                } catch (NoSuchElementException e) {
                    return false;
                }
                return true;
            }

            @Override
            public T next() {
                if (next==null) {
                    return readNext();
                }
                T ret = next;
                next = null;
                return ret;
            }

            @Override
            public void remove() {
                throw new UnsupportedOperationException();
            }

            @SuppressWarnings("unchecked")
            private T readNext() {
                if (ois==null) {
                    throw new NoSuchElementException();
                }
                try {
                    return (T) ois.readObject();
                } catch (IOException e) {
                    cleanUp();
                    throw new NoSuchElementException();
                } catch (ClassNotFoundException e) {
                    cleanUp();
                    throw new NoSuchElementException();
                }
            }

            /** Clean up InputStream right away if we reached the last entry in the stream */
            private void cleanUp() {
                oiss.remove(ois);
                try {
                    ois.close();
                } catch (IOException e) {
                    log.error(e.getMessage(), e);
                }
            }
        };
    }

    @Override
    public boolean remove(Object arg0) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeAll(Collection<?> arg0) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean retainAll(Collection<?> arg0) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public Object[] toArray() {
        throw new UnsupportedOperationException();  // This is not really an optional operation for a Collection
    }

    @Override
    public <T2> T2[] toArray(final T2[] arg0) {
        throw new UnsupportedOperationException();  // This is not really an optional operation for a Collection
    }
}
