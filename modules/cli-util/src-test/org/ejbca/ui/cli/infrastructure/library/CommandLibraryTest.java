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
package org.ejbca.ui.cli.infrastructure.library;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
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
import org.primekey.anttools.ServiceManifestBuilder;

/**
 * @version $Id$
 *
 */
public class CommandLibraryTest {

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
        ServiceManifestBuilder.buildServiceManifestToLocation(temporarySourceDirectory, CliCommandPlugin.class);
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

    private static final String TESTCLASS = "import org.ejbca.ui.cli.infrastructure.command.CliCommandPlugin; import java.util.Set; import java.util.HashSet; " + "public class MockCommand implements CliCommandPlugin { "
            + "public void execute(String... arguments) { } "
            + "public String getCommandDescription() { return \"\";} "
            + "public String getMainCommand() { return \"foo\"; } "
            + "public Set<String> getMainCommandAliases() { Set<String> aliases = new HashSet<String>(); aliases.add(\"bar\"); return aliases; } "
            + "public String[] getCommandPath() { return new String[] { \"alpha\", \"beta\" };} "
            + " public Set<String[]> getCommandPathAliases() { Set<String[]> aliases = new HashSet<String[]>(); aliases.add(new String[] { \"aleph\", \"bet\" }); return aliases; }"
            + "}";

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
