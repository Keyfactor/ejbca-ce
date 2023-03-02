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

import com.keyfactor.util.StreamSizeLimitExceededException;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Unpacks zip files securely. Follows best practices according to
 * <a href="https://wiki.sei.cmu.edu/confluence/display/java/IDS04-J.+Safely+extract+files+from+ZipInputStream">IDS04-J</a>
 * and allows the programmer to limit the number of files as well as the number of bytes which can be processed.
 *
 * <p>The programmer can also filter which files to unpack based on file extension and add callbacks
 * for different events, such as when a file is skipped, unpacked or whenever an error occurs.
 *
 * <p><b>Example usage:</b>
 * <pre>
 *     final SecureZipUnpacker zip = SecureZipUnpacker.Builder.fromByteArray(myZipFile)
 *         .onFileIgnored((zipEntry, acceptedFileExtensions) -> System.out.println("Ignored file " + zipEntry.getName()))
 *         .onFileUnpacked(zipEntry -> System.out.println("Unpacked file " + zipEntry.getName()))
 *         .onError(error -> System.err.println("An error occurred: " + e.getMessage())
 *         .onlyUnpackFilesWithFileExtension(".txt")
 *         .withMaximumNumberOfFiles(10)
 *         .withAMaximumSizeOf(1024 * 1024) // 1 MB
 *         .build()
 *     for (final UnpackedFile textFile : zip.unpackFilesToMemory()) {
 *         // Do something with the unpacked file
 *     }
 * </pre>
 *
 * @version $Id$
 */
public class SecureZipUnpacker {
    private static final Logger log = Logger.getLogger(SecureZipUnpacker.class);

    private final ZipInputStream zipInputStream;
    private final int maxFileCount;
    private final long maxSize;
    private final List<String> acceptedFileExtensions;
    private final OnErrorListener onErrorListener;
    private final OnFileIgnoredListener onFileIgnoredListener;
    private final OnFileUnpackedListener onFileUnpackedListener;

    private long totalNumberOfBytesRead = 0;

    /**
     * Creates a new builder of {@link SecureZipUnpacker} objects.
     *
     * <p>By default, the {@link SecureZipUnpacker} object built by this builder is restricted to
     * unpack no more than 256 files, where each (uncompressed) file is allowed to be at most 512 kB large.
     *
     * <p>Events are logged using a {@link Logger} and all file extensions are accepted.
     */
    public static class Builder {
        private final ZipInputStream zipInputStream;
        private int maxFileCount = 256;
        private long maxSize = 1024 * 1024 * 32; // 32 MB
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

        /**
         * Create a new builder from a zip file represented by an array of bytes.
         *
         * @param byteArray a zip file.
         * @return a builder of {@link SecureZipUnpacker} objects.
         */
        public static Builder fromByteArray(final byte[] byteArray) {
            return new Builder(new ZipInputStream(new ByteArrayInputStream(byteArray)));
        }

        /**
         * Create a new builder from a {@link ZipInputStream}.
         *
         * @param zipInputStream a zip input stream
         * @return a builder
         */
        public static Builder fromZipInputStream(final ZipInputStream zipInputStream) {
            return new Builder(zipInputStream);
        }

        protected Builder(final ZipInputStream zipInputStream) {
            this.zipInputStream = zipInputStream;
        }

        /**
         * Restrict the number of files in the zip file.
         *
         * <p>If the zip file contains more files than what is being specified here, {@link IOException} is produced
         * during extraction and the callback function set with {@link #onError(OnErrorListener)} is invoked.
         *
         * <p>Files being ignored due to their file extension are also counted towards this quota.
         *
         * @param maxFileCount the maximum number of files to allow in the zip file
         * @return the builder.
         */
        public Builder withMaximumNumberOfFiles(final int maxFileCount) {
            this.maxFileCount = maxFileCount;
            return this;
        }

        /**
         * Restrict the number of bytes which can be processed by the {@link SecureZipUnpacker}.
         *
         * <p>If more bytes than what is being specified here is encountered, {@link IOException} is produced and the
         * callback function set with {@link #onError(OnErrorListener)} is invoked.
         *
         * @see <a href="https://en.wikipedia.org/wiki/Zip_bomb">Zip bomb</a>
         *
         * @param maxSize the maximum size of the uncompressed zip file in bytes.
         * @return the builder.
         */
        public Builder withAMaximumSizeOf(final long maxSize) {
            this.maxSize = maxSize;
            return this;
        }

        /**
         * Restrict which files to unpack based on file extension.
         *
         * @param fileExtension a file extension, e.g. ".css" or ".txt".
         * @return the builder.
         */
        public Builder onlyUnpackFilesWithFileExtension(final String fileExtension) {
            this.acceptedFileExtensions = Arrays.asList(fileExtension);
            return this;
        }

        /**
         * Register a callback function invoked on errors.
         *
         * @param onErrorListener a callback function.
         * @return the builder.
         */
        public Builder onError(final OnErrorListener onErrorListener) {
            this.onErrorListener = onErrorListener;
            return this;
        }

        /**
         * Register a callback function invoked whenever a file is skipped because it has the wrong file extension.
         *
         * @param onFileIgnoredListener a callback function.
         * @return the builder.
         */
        public Builder onFileIgnored(final OnFileIgnoredListener onFileIgnoredListener) {
            this.onFileIgnoredListener = onFileIgnoredListener;
            return this;
        }

        /**
         * Register a callback function invoked whenever a file has been unpacked successfully.
         *
         * @param onFileUnpackedListener a callback function.
         * @return the builder.
         */
        public Builder onFileUnpacked(final OnFileUnpackedListener onFileUnpackedListener) {
            this.onFileUnpackedListener = onFileUnpackedListener;
            return this;
        }

        /**
         * Build an instance of {@link SecureZipUnpacker}.
         *
         * @return the instance.
         */
        public SecureZipUnpacker build() {
            return new SecureZipUnpacker(this);
        }
    }

    /**
     * Represents an unpacked file stored in memory.
     */
    public static class UnpackedFile {
        private final String fileName;
        private final byte[] bytes;

        protected UnpackedFile(final String fileName, final byte[] bytes) {
            this.fileName = fileName;
            this.bytes = bytes;
        }

        /**
         * Returns the content of the file as an array of bytes.
         *
         * @return a byte array.
         */
        public byte[] getContentAsBytes() {
            return bytes;
        }

        /**
         * Returns the name of the file as specified by {@link ZipEntry#getName()}.
         *
         * @return a the name of file.
         */
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
        this.zipInputStream = builder.zipInputStream;
        this.maxFileCount = builder.maxFileCount;
        this.maxSize = builder.maxSize;
        this.acceptedFileExtensions = builder.acceptedFileExtensions;
        this.onFileIgnoredListener = builder.onFileIgnoredListener;
        this.onErrorListener = builder.onErrorListener;
        this.onFileUnpackedListener = builder.onFileUnpackedListener;
    }

    /**
     * Unpack a zip file to memory.
     *
     * @return a list of unpacked files or an empty list if an error occurred.
     */
    public List<UnpackedFile> unpackFilesToMemory() {
        try {
            return unpackFilesAsList();
        } catch (IOException e) {
            onErrorListener.onError(e);
            return Collections.emptyList();
        }
    }

    private List<UnpackedFile> unpackFilesAsList() throws IOException {
        try {
            final List<UnpackedFile> unpackedFiles = new ArrayList<>();
            ZipEntry zipEntry;
            int fileCount = 0;
            while ((zipEntry = zipInputStream.getNextEntry()) != null) {
                if (zipEntry.isDirectory()) {
                    continue;
                }
                if (++fileCount > maxFileCount) {
                    throw new FileLimitExceededException("Only up to " + maxFileCount + " files is allowed to be processed.");
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
        } finally {
            zipInputStream.close();
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
            final byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = zipInputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, bytesRead);
                totalNumberOfBytesRead += bytesRead;
                if (totalNumberOfBytesRead > maxSize) {
                    throw new StreamSizeLimitExceededException("Not permitted to decompress more than " + maxSize
                            + " bytes of data. The limit was exceeded when extracting the file " + zipEntry.getName() + ".");
                }
            }
            return byteArrayOutputStream.toByteArray();
        }
    }
}
