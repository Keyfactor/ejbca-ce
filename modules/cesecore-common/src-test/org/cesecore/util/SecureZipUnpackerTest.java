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

import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.junit.Test;

import com.keyfactor.util.StreamSizeLimitExceededException;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Unit tests for {@link SecureZipUnpacker}.
 *
 * @version $Id$
 */
public class SecureZipUnpackerTest {

    @Test
    public void unpack1FileToMemory() throws IOException {
        final ZipInputStream zipInputStream = mock(ZipInputStream.class);
        final ZipEntry zipEntry = mock(ZipEntry.class);
        final SecureZipUnpacker.OnFileUnpackedListener onFileUnpackedListener = mock(SecureZipUnpacker.OnFileUnpackedListener.class);
        expect(zipInputStream.getNextEntry())
                .andReturn(zipEntry)
                .once()
                .andReturn(null)
                .once();
        expect(zipInputStream.read(anyObject(byte[].class)))
                .andReturn(1)
                .once()
                .andReturn(-1)
                .once();
        expect(zipEntry.getName())
                .andReturn("foo")
                .anyTimes();
        expect(zipEntry.isDirectory())
                .andReturn(false)
                .once();
        onFileUnpackedListener.onFileUnpacked(eq(zipEntry));
        expectLastCall().once();
        zipInputStream.close();
        expectLastCall().once();
        zipInputStream.closeEntry();
        expectLastCall().once();
        replay(zipInputStream, zipEntry);
        final List<SecureZipUnpacker.UnpackedFile> unpackedFiles = SecureZipUnpacker.Builder
                .fromZipInputStream(zipInputStream)
                .withMaximumNumberOfFiles(1)
                .withAMaximumSizeOf(1)
                .onFileUnpacked(onFileUnpackedListener)
                .build()
                .unpackFilesToMemory();
        verify(zipInputStream, zipEntry);
        assertEquals(1, unpackedFiles.size());
        final SecureZipUnpacker.UnpackedFile foo = unpackedFiles.get(0);
        assertEquals("foo", foo.getFileName());
        assertArrayEquals(new byte[] { 0 }, foo.getContentAsBytes());
    }

    @Test
    public void unpack1CssFile() throws IOException {
        final ZipInputStream zipInputStream = mock(ZipInputStream.class);
        final ZipEntry txtFile = mock(ZipEntry.class);
        final ZipEntry cssFile = mock(ZipEntry.class);
        final ZipEntry directory = mock(ZipEntry.class);
        final SecureZipUnpacker.OnFileUnpackedListener onFileUnpackedListener = mock(SecureZipUnpacker.OnFileUnpackedListener.class);
        expect(zipInputStream.getNextEntry())
                .andReturn(directory)
                .once()
                .andReturn(txtFile)
                .once()
                .andReturn(cssFile)
                .once()
                .andReturn(null)
                .once();
        expect(zipInputStream.read(anyObject(byte[].class)))
                .andReturn(1)
                .once()
                .andReturn(-1)
                .once();
        expect(cssFile.getName())
                .andReturn("foo.css")
                .anyTimes();
        expect(txtFile.getName())
                .andReturn("foo.txt")
                .anyTimes();
        expect(cssFile.isDirectory())
                .andReturn(false)
                .once();
        expect(txtFile.isDirectory())
                .andReturn(false)
                .once();
        expect(directory.isDirectory())
                .andReturn(true)
                .once();
        onFileUnpackedListener.onFileUnpacked(eq(cssFile));
        expectLastCall().once();
        onFileUnpackedListener.onFileUnpacked(eq(txtFile));
        expectLastCall().once();
        zipInputStream.close();
        expectLastCall().once();
        zipInputStream.closeEntry();
        expectLastCall().once();
        replay(zipInputStream, cssFile, txtFile, directory);
        final List<SecureZipUnpacker.UnpackedFile> unpackedFiles = SecureZipUnpacker.Builder
                .fromZipInputStream(zipInputStream)
                .withMaximumNumberOfFiles(2)
                .withAMaximumSizeOf(1)
                .onFileUnpacked(onFileUnpackedListener)
                .onlyUnpackFilesWithFileExtension(".css")
                .build()
                .unpackFilesToMemory();
        verify(zipInputStream, cssFile, txtFile, directory);
        assertEquals(1, unpackedFiles.size());
        final SecureZipUnpacker.UnpackedFile fooCss = unpackedFiles.get(0);
        assertEquals("foo.css", fooCss.getFileName());
        assertArrayEquals(new byte[] { 0 }, fooCss.getContentAsBytes());
    }

    @Test
    public void unpackTooLargeFile() throws IOException {
        final ZipInputStream zipInputStream = mock(ZipInputStream.class);
        final ZipEntry zipEntry = mock(ZipEntry.class);
        final SecureZipUnpacker.OnErrorListener onErrorListener = mock(SecureZipUnpacker.OnErrorListener.class);
        expect(zipInputStream.getNextEntry())
                .andReturn(zipEntry)
                .once();
        expect(zipInputStream.read(anyObject(byte[].class)))
                .andReturn(1)
                .times(2);
        expect(zipEntry.getName())
                .andReturn("foo")
                .anyTimes();
        expect(zipEntry.isDirectory())
                .andReturn(false)
                .once();
        onErrorListener.onError(anyObject(StreamSizeLimitExceededException.class));
        expectLastCall().once();
        zipInputStream.close();
        expectLastCall().once();
        replay(zipInputStream, zipEntry);
        final List<SecureZipUnpacker.UnpackedFile> unpackedFiles = SecureZipUnpacker.Builder
                .fromZipInputStream(zipInputStream)
                .withMaximumNumberOfFiles(1)
                .withAMaximumSizeOf(1)
                .onError(onErrorListener)
                .build()
                .unpackFilesToMemory();
        verify(zipInputStream, zipEntry);
        assertNotNull(unpackedFiles);
        assertEquals(0, unpackedFiles.size());
    }

    @Test
    public void unpackTooManyFiles() throws IOException {
        final ZipInputStream zipInputStream = mock(ZipInputStream.class);
        final ZipEntry zipEntry1 = mock(ZipEntry.class);
        final ZipEntry zipEntry2 = mock(ZipEntry.class);
        final SecureZipUnpacker.OnErrorListener onErrorListener = mock(SecureZipUnpacker.OnErrorListener.class);
        expect(zipInputStream.getNextEntry())
                .andReturn(zipEntry1)
                .once()
                .andReturn(zipEntry2)
                .once();
        expect(zipInputStream.read(anyObject(byte[].class)))
                .andReturn(1)
                .times(1)
                .andReturn(-1)
                .once();
        expect(zipEntry1.getName())
                .andReturn("foo1")
                .anyTimes();
        expect(zipEntry1.isDirectory())
                .andReturn(false)
                .once();
        expect(zipEntry2.getName())
                .andReturn("foo2")
                .anyTimes();
        expect(zipEntry2.isDirectory())
                .andReturn(false)
                .once();
        onErrorListener.onError(anyObject(FileLimitExceededException.class));
        expectLastCall().once();
        zipInputStream.close();
        expectLastCall().once();
        zipInputStream.closeEntry();
        expectLastCall().once();
        replay(zipInputStream, zipEntry1, zipEntry2);
        final List<SecureZipUnpacker.UnpackedFile> unpackedFiles = SecureZipUnpacker.Builder
                .fromZipInputStream(zipInputStream)
                .withMaximumNumberOfFiles(1)
                .withAMaximumSizeOf(1)
                .onError(onErrorListener)
                .build()
                .unpackFilesToMemory();
        verify(zipInputStream, zipEntry1, zipEntry2);
        assertNotNull(unpackedFiles);
        assertEquals(0, unpackedFiles.size());
    }
}