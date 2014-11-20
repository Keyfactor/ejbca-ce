/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.primekey.anttools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;
import java.util.jar.JarFile;

import javax.tools.JavaCompiler;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Contains unit tests for the ServiceManifestBuilder class. 
 * 
 * @version $Id$
 *
 */
public class ServiceManifestBuilderTest {

    private static final Logger log = Logger.getLogger(ServiceManifestBuilderTest.class);
    private static final String DUMMY_PACKAGE = "org.foo.bar";
    private static final String FIRST_DUMMY_INTERFACE_NAME = "FirstDummyInterface";
    private static final String SECOND_DUMMY_INTERFACE_NAME = "SecondDummyInterface";

    private File temporaryFileDirectory;
    private File temporarySourceDirectory;

    @Before
    public void setup() throws IOException {
        log.trace(">setup");
        //Create a temporary file directory that we'll add to the classpath
        temporaryFileDirectory = ServiceManifestBuilder.createTempDirectory();
        temporarySourceDirectory = ServiceManifestBuilder.createTempDirectory(temporaryFileDirectory);
        //Let's do the ugliest hack of hacks and add that directory to the classpath at runtime
        URLClassLoader sysloader = (URLClassLoader) ClassLoader.getSystemClassLoader();
        try {
            Method method = URLClassLoader.class.getDeclaredMethod("addURL", new Class[] { URL.class });
            method.setAccessible(true);
            method.invoke(sysloader, new Object[] { temporarySourceDirectory.toURI().toURL() });
        } catch (Throwable t) {
            throw new RuntimeException("Exception caught while trying to haxxor classpath", t);
        }

        //Thought that was bad? Hah! Let's create dummy implementations from a dummy interface and put them in the tempdir to simulate a .jar
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        JavaFileObject firstDummyInterface = new JavaSourceFromString(FIRST_DUMMY_INTERFACE_NAME, "package " + DUMMY_PACKAGE + "; public interface "
                + FIRST_DUMMY_INTERFACE_NAME + " {}");
        JavaFileObject secondDummyInterface = new JavaSourceFromString(SECOND_DUMMY_INTERFACE_NAME, "package " + DUMMY_PACKAGE
                + "; public interface " + SECOND_DUMMY_INTERFACE_NAME + " {}");
        //You thought I was kidding, weren't you?
        JavaFileObject firstImplentation = new JavaSourceFromString("FirstImplementation", "package " + DUMMY_PACKAGE
                + "; public class FirstImplementation implements " + FIRST_DUMMY_INTERFACE_NAME + ", " + SECOND_DUMMY_INTERFACE_NAME + " {}");
        //Hah! No such luck!
        JavaFileObject secondImplementation = new JavaSourceFromString("SecondImplementation", "package " + DUMMY_PACKAGE
                + "; public class SecondImplementation implements " + FIRST_DUMMY_INTERFACE_NAME + ", " + SECOND_DUMMY_INTERFACE_NAME + " {}");
        List<JavaFileObject> compilationUnits = Arrays.asList(firstDummyInterface, secondDummyInterface, firstImplentation, secondImplementation);
        final List<String> options = Arrays.asList("-d", temporarySourceDirectory.toString());
        CompilationTask task = javac.getTask(null, null, null, options, null, compilationUnits);
        if (!task.call()) {
            log.error("Compilation of test classes failed, can't continue");
            throw new RuntimeException("Compilation of test classes failed, can't continue");
        }
        log.trace("<setup");
    }

    @After
    public void tearDown() throws IOException {
        if (temporaryFileDirectory.exists()) {
            ServiceManifestBuilder.delete(temporaryFileDirectory);
        }
    }

    @Test
    public void testBuildServiceManifestToClassPath() throws IOException, ClassNotFoundException {
        Class<?> dummyInterfaceClass = Class.forName(DUMMY_PACKAGE + "." + FIRST_DUMMY_INTERFACE_NAME);
        //Phew, it won't get uglier than this at least. 
        ServiceManifestBuilder.buildServiceManifestToLocation(temporarySourceDirectory, dummyInterfaceClass);
        //Loverly. We should now have a manifest file on the classpath
        ServiceLoader<?> serviceLoader = ServiceLoader.load(dummyInterfaceClass);
        Iterator<?> serviceIterator = serviceLoader.iterator();
        int objectsInServiceLoader = 0;
        while (serviceIterator.hasNext()) {
            objectsInServiceLoader++;
            serviceIterator.next();
        }
        assertEquals("Wrong number of objects returned by service loader", 2, objectsInServiceLoader);
    }

    @Test
    public void testBuildServiceManifestToClassPathWithMultipleInterfaces() throws IOException, ClassNotFoundException {
        Class<?> firstDummyInterfaceClass = Class.forName(DUMMY_PACKAGE + "." + FIRST_DUMMY_INTERFACE_NAME);
        Class<?> secondDummyInterfaceClass = Class.forName(DUMMY_PACKAGE + "." + SECOND_DUMMY_INTERFACE_NAME);

        //Phew, it won't get uglier than this at least. 
        ServiceManifestBuilder.buildServiceManifestToLocation(temporarySourceDirectory, firstDummyInterfaceClass, secondDummyInterfaceClass);
        //Loverly. We should now have a manifest file on the classpath
        {
            ServiceLoader<?> serviceLoader = ServiceLoader.load(firstDummyInterfaceClass);
            Iterator<?> serviceIterator = serviceLoader.iterator();
            int objectsInServiceLoader = 0;
            while (serviceIterator.hasNext()) {
                objectsInServiceLoader++;
                serviceIterator.next();
            }
            assertEquals("Wrong number of objects returned by service loader", 2, objectsInServiceLoader);
        }
        {

            ServiceLoader<?> serviceLoader = ServiceLoader.load(secondDummyInterfaceClass);
            Iterator<?> serviceIterator = serviceLoader.iterator();
            int objectsInServiceLoader = 0;
            while (serviceIterator.hasNext()) {
                objectsInServiceLoader++;
                serviceIterator.next();
            }
            assertEquals("Wrong number of objects returned by service loader", 2, objectsInServiceLoader);
        }
    }

    @Test
    public void testMainMethod() throws IOException {
        log.info(">testMainMethod");
        File jarFile = File.createTempFile("tmp", ".jar", temporaryFileDirectory);
        try {
            //Now, let's make a jar out of our dummy classes. 
            ServiceManifestBuilder.writeFileStructuretoJar(temporarySourceDirectory, jarFile, null);
            String[] args = {jarFile.getAbsolutePath(), DUMMY_PACKAGE + "." + FIRST_DUMMY_INTERFACE_NAME};
            final int exitCode = ServiceManifestBuilder.mainInternal(args);
            assertEquals("Process exited with non-zero error level.", 0, exitCode);
            JarFile result = new JarFile(jarFile);
            try {
                assertTrue("Manifest file was not created.",
                        result.getEntry("/META-INF/services/" + DUMMY_PACKAGE + "." + FIRST_DUMMY_INTERFACE_NAME) != null);
            } finally {
                if (result != null) {
                    result.close();
                }
            }
        } finally {
            try {
                jarFile.delete();
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }
        log.info("<testMainMethod");
    }

}

class JavaSourceFromString extends SimpleJavaFileObject {
    final String code;

    JavaSourceFromString(String name, String code) {
        super(URI.create("string:///" + name.replace('.', '/') + Kind.SOURCE.extension), Kind.SOURCE);
        this.code = code;
    }

    @Override
    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
        return code;
    }
}
