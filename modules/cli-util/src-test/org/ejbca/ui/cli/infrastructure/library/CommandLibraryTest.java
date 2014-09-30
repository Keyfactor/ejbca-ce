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
package org.ejbca.ui.cli.infrastructure.library;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.tools.JavaCompiler;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

import org.cesecore.util.FileTools;
import org.ejbca.ui.cli.infrastructure.command.CliCommandPlugin;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CommandLibraryTest {

    private static final String CLASS_EXTENSION = ".class";
    private static final String META_INF = "META-INF";
    private static final String SERVICES = "services";
    
    private static final String TESTCLASS = "import org.ejbca.ui.cli.infrastructure.command.CliCommandPlugin; import java.util.Set; import java.util.HashSet; import org.ejbca.ui.cli.infrastructure.command.CommandResult;"
            + "public class MockCommand implements CliCommandPlugin { "
            + "public CommandResult execute(String... arguments) { return CommandResult.SUCCESS; } "
            + "public String getCommandDescription() { return \"\";} "
            + "public String getMainCommand() { return \"foo\"; } "
            + "public Set<String> getMainCommandAliases() { Set<String> aliases = new HashSet<String>(); aliases.add(\"bar\"); return aliases; } "
            + "public String[] getCommandPath() { return new String[] { \"alpha\", \"beta\" };} "
            + " public Set<String[]> getCommandPathAliases() { Set<String[]> aliases = new HashSet<String[]>(); aliases.add(new String[] { \"aleph\", \"bet\" }); return aliases; }"
            + "}";
    
    private File temporaryFileDirectory;
    private File temporarySourceDirectory;

    @Before
    public void setup() throws IOException {
        //Create a temporary file directory that we'll add to the classpath
        temporaryFileDirectory = FileTools.createTempDirectory();
        temporarySourceDirectory = FileTools.createTempDirectory(temporaryFileDirectory);
        //Let's do the ugliest hack of hacks and add that directory to the classpath at runtime
        URLClassLoader sysloader = (URLClassLoader) ClassLoader.getSystemClassLoader();
        try {
            Method method = URLClassLoader.class.getDeclaredMethod("addURL", new Class[] { URL.class });
            method.setAccessible(true);
            method.invoke(sysloader, new Object[] { temporarySourceDirectory.toURI().toURL() });
        } catch (Throwable t) {
            throw new RuntimeException("Exception caught while trying to haxxor classpath", t);
        }
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        JavaFileObject firstImplentation = new JavaSourceFromString("MockCommand", TESTCLASS);
        List<JavaFileObject> compilationUnits = Arrays.asList(firstImplentation);
        final List<String> options = Arrays.asList("-d", temporarySourceDirectory.toString());
        CompilationTask task = javac.getTask(null, null, null, options, null, compilationUnits);
        if (!task.call()) {
            throw new RuntimeException("Compilation of test classes failed, can't continue");
        }
        buildServiceManifestToLocation(temporarySourceDirectory, CliCommandPlugin.class);
    }
    
    /**
     * Method that constructs a file to any location. Can be a jarfile, directly to the classpath, you name it. 
     * 
     * @param location a writable location where a META-INF/services directory will be created (if not existing) and a manifest file placed,
     *                 and where suitable class files will be searched for.
     * @param interfaceClass the interface to base the manifest on
     * @throws IOException for any file related errors
     */
    private static void buildServiceManifestToLocation(File location, Class<?>... interfaceClasses) throws IOException {
        if (!location.isDirectory()) {
            throw new IOException("File " + location + " was not a directory.");
        }
        if (!location.canWrite() && !location.canRead()) {
            throw new IOException("Could not read/write to directory " + location);
        }
        for (Class<?> interfaceClass : interfaceClasses) {
            if (!interfaceClass.isInterface()) {
                throw new IllegalArgumentException("Class " + interfaceClass.getName() + " was not an interface.");
            }
            List<Class<?>> implementingClasses = getImplementingClasses(location, location, interfaceClass);
            System.out.println("Added " + implementingClasses.size() + " implementations of " + interfaceClass.getName());
            File metaInf = new File(location, META_INF);
            if (!metaInf.exists()) {
                if (!metaInf.mkdir()) {
                    throw new IOException("Could not create directory " + metaInf);
                }
            }
            File servicesDirectory = new File(metaInf, SERVICES);
            if (!servicesDirectory.exists()) {
                if (!servicesDirectory.mkdirs()) {
                    throw new IOException("Could not create directory " + servicesDirectory);
                }
            }
            final File manifestFile = new File(servicesDirectory, interfaceClass.getName());
            if (!manifestFile.exists()) {
                if (!manifestFile.createNewFile()) {
                    throw new IOException("Could not create manifest file.");
                }
            }
            PrintWriter printWriter = new PrintWriter(manifestFile);
            try {
                for (Class<?> implementingClass : implementingClasses) {
                    printWriter.println(implementingClass.getName());
                }
            } finally {
                printWriter.flush();
                printWriter.close();
            }
        }
    }
    
    @After
    public void tearDown() throws IOException {
        if (temporaryFileDirectory.exists()) {
            FileTools.delete(temporaryFileDirectory);
        }
    }

    @Test
    public void testStandardCommand() {
        assertTrue("Standard command could not be found.", CommandLibrary.INSTANCE.doesCommandExist("alpha", "beta", "foo"));
    }
    
    @Test 
    public void testStandardCommandAlias() {
        assertTrue("Standard command could not be found.", CommandLibrary.INSTANCE.doesCommandExist("alpha", "beta", "bar"));
    }
    
    @Test
    public void testAlternativeCommandPath() {
        assertTrue("Standard command could not be found.", CommandLibrary.INSTANCE.doesCommandExist("aleph", "bet", "foo"));
    }


    /**
     * Recursive method which recursively seeks out all classes implementing a certain interface
     * 
     * @param baseLocation File from which the search was started
     * @param location local file in which to search
     * @param interfaceClass an interface to search for
     * @return a list of classes implementing the given interface
     * @throws IOException 
     */
    private static List<Class<?>> getImplementingClasses(final File baseLocation, File location, Class<?> interfaceClass) {
        List<Class<?>> result = new ArrayList<Class<?>>();
        if (location.isDirectory()) {
            //Recurse to find all files in all subdirectories
            for (File file : location.listFiles()) {
                if (file.isDirectory()) {
                    result.addAll(getImplementingClasses(baseLocation, file, interfaceClass));
                } else {
                    if (file.getName().toLowerCase().endsWith(CLASS_EXTENSION)) {
                        String className = file
                                .getAbsolutePath()
                                .substring(baseLocation.getAbsolutePath().length() + File.separator.length(),
                                        file.getAbsolutePath().indexOf(CLASS_EXTENSION)).replace(File.separatorChar, '.');
                        try {
                            Class<?> candidate = Class.forName(className);
                            if (interfaceClass.isAssignableFrom(candidate) && !Modifier.isAbstract(candidate.getModifiers())
                                    && !candidate.isInterface()) {                              
                                result.add(candidate);
                            }
                        } catch (ClassNotFoundException e) {
                            throw new IllegalArgumentException("Class of name " + className + " was not found, even though a class file"
                                    + " of that name was found in " + baseLocation.getAbsolutePath(), e);
                        }
                    }
                }
            }
           
        }
        return result;
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

