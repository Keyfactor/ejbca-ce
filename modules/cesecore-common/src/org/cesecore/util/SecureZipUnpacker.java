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

import org.apache.log4j.Logger;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Unpacks zip files securely. Allows the programmer to specify a limit of the number of files
 * to process as well as restrict the size of individual files.
 */
public class SecureZipUnpacker {
    private static final Logger log = Logger.getLogger(SecureZipUnpacker.class);

    private final InputStream inputStream;
    private final int maxFileCount;
    private final int maxSize;
    private final List<String> acceptedFileExtensions;
    private final OnErrorListener onErrorListener;
    private final OnFileIgnoredListener onFileIgnoredListener;
    private final OnFileUnpackedListener onFileUnpackedListener;

    public static class Builder {
        private final InputStream inputStream;
        private int maxFileCount = 256;
        private int maxSize = 1024 * 512;
        private List<String> acceptedFileExtensions;
        private OnErrorListener onErrorListener = e -> {
            log.error(e);
        };
        private OnFileIgnoredListener onFileIgnoredListener = (zipEntry, acceptedFileExtensions) -> {
            log.info("The file " + zipEntry.getName() + " was ignored. Only files with one of the file extensions " + acceptedFileExtensions + " is processed.");
        };
        private OnFileUnpackedListener onFileUnpackedListener = (zipEntry -> {
            log.info("Unpacked file " + zipEntry.getName() + ".");
        });

        public static Builder fromByteArray(final byte[] byteArray) {
            return new Builder(new ByteArrayInputStream(byteArray));
        }

        public Builder(final InputStream inputStream) {
            this.inputStream = inputStream;
        }

        public Builder withMaximumNumberOfFiles(final int maxFileCount) {
            this.maxFileCount = maxFileCount;
            return this;
        }

        public Builder withEachFileLessThan(final int maxSize) {
            this.maxSize = maxSize;
            return this;
        }

        public Builder onlyUnpackFilesWithFileExtension(final String fileExtension) {
            this.acceptedFileExtensions = Arrays.asList(fileExtension);
            return this;
        }

        public Builder onError(final OnErrorListener onErrorListener) {
            this.onErrorListener = onErrorListener;
            return this;
        }

        public Builder onFileIgnored(final OnFileIgnoredListener onFileIgnoredListener) {
            this.onFileIgnoredListener = onFileIgnoredListener;
            return this;
        }

        public Builder onFileUnpacked(final OnFileUnpackedListener onFileUnpackedListener) {
            this.onFileUnpackedListener = onFileUnpackedListener;
            return this;
        }

        public SecureZipUnpacker build() {
            return new SecureZipUnpacker(this);
        }
    }

    public static class UnpackedFile {
        private final String fileName;
        private final byte[] bytes;

        public UnpackedFile(final String fileName, final byte[] bytes) {
            this.fileName = fileName;
            this.bytes = bytes;
        }

        public byte[] getContentAsBytes() {
            return bytes;
        }

        public String getFileName() {
            return fileName;
        }
    }

    public interface OnErrorListener {
        void onError(final IOException e);
    }

    public interface OnFileIgnoredListener {
        void onFileIgnored(final ZipEntry zipEntry, final List<String> acceptedFileExtensions);
    }

    public interface OnFileUnpackedListener {
        void onFileUnpacked(final ZipEntry zipEntry);
    }

    protected SecureZipUnpacker(final Builder builder) {
        this.inputStream = builder.inputStream;
        this.maxFileCount = builder.maxFileCount;
        this.maxSize = builder.maxSize;
        this.acceptedFileExtensions = builder.acceptedFileExtensions;
        this.onFileIgnoredListener = builder.onFileIgnoredListener;
        this.onErrorListener = builder.onErrorListener;
        this.onFileUnpackedListener = builder.onFileUnpackedListener;
    }

    public List<UnpackedFile> unpackFilesToMemory() {
        try {
            return unpackFilesAsList();
        } catch (IOException e) {
            onErrorListener.onError(e);
            return Collections.emptyList();
        }
    }

    private List<UnpackedFile> unpackFilesAsList() throws IOException {
        try (final ZipInputStream zipInputStream = new ZipInputStream(inputStream)) {
            final List<UnpackedFile> unpackedFiles = new ArrayList<>();
            ZipEntry zipEntry;
            int fileCount = 0;
            while ((zipEntry = zipInputStream.getNextEntry()) != null) {
                if (zipEntry.isDirectory()) {
                    continue;
                }
                if (++fileCount > maxFileCount) {
                    throw new SecurityException("Only up to " + maxFileCount + " files is allowed to be processed.");
                }
                if (!isAcceptedFileExtension(zipEntry.getName())) {
                    onFileIgnoredListener.onFileIgnored(zipEntry, acceptedFileExtensions);
                    continue;
                }
                final byte[] bytes = readZipEntry(zipInputStream, zipEntry);
                unpackedFiles.add(new UnpackedFile(zipEntry.getName(), bytes));
                onFileUnpackedListener.onFileUnpacked(zipEntry);
                zipInputStream.closeEntry();
            }
            return unpackedFiles;
        }
    }

    private boolean isAcceptedFileExtension(final String fileName) {
        if (acceptedFileExtensions == null) {
            // Allow all files, this is the default
            return true;
        }
        return acceptedFileExtensions.stream().anyMatch(fileExtension -> fileName.endsWith(fileExtension));
    }

    private byte[] readZipEntry(final ZipInputStream zipInputStream, final ZipEntry zipEntry) throws IOException {
        try (final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            final byte[] buffer = new byte[Math.max(maxSize / 512, 1024)];
            int totalNumberOfBytesRead = 0;
            int bytesRead;
            while ((bytesRead = zipInputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, bytesRead);
                totalNumberOfBytesRead += bytesRead;
                if (totalNumberOfBytesRead > maxSize) {
                    throw new IOException("The size of the file " + zipEntry.getName() + " exceeds the limit of " + maxSize + " bytes.");
                }
            }
            return byteArrayOutputStream.toByteArray();
        }
    }
}
