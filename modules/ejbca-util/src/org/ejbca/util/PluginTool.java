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

package org.ejbca.util;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.apache.log4j.Logger;

/**
 * Helper for finding classes from class-path that implement a specified interface
 * 
 * This is used for the EJBCA EJB CLI. It might not work inside an EAR and might require modifications.
 *
 * @version $Id$
 */
public class PluginTool {
	
	private static final Logger log = Logger.getLogger(PluginTool.class);

	/**
	 * Returns all classes that implement a given interface class
	 * @param packageName can be given to only process resources that contain the specific package. This will greatly speed up the search. Use null to search through all JARs.
	 * @param interfaceClass is the interface class to search for
	 * @param checkSuperClasses will include a class if one of its super classes implements the interface
	 * @return a list of classes that implements this interface
	 */
	public static List<Class<?>> getSome(String packageName, Class<?> interfaceClass, boolean checkSuperClasses) {
		log.trace(">getSome");
		long start = new Date().getTime();
		List<Class<?>> implementationList = new ArrayList<Class<?>>();
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		try {
			List<File> jarFileList = new ArrayList<File>();
			if (packageName == null || "".equals(packageName)) {
				packageName = "";
				// Locate all JAR files from root (this will include jar that are not in the class-path. but we will skip them later on..)
				Enumeration<URL> allResources = classLoader.getResources("");
				while (allResources.hasMoreElements()) {
					URL url = allResources.nextElement();
					log.debug("url: " + url.getPath());
					File file = new File(URLDecoder.decode(url.getPath(), "UTF-8"));
					log.debug("Got directory: " + file.getAbsolutePath());
					addJarsFromDir(file, jarFileList);
				}
			} else {
				// Less insane approach when we know the base package name
				packageName = packageName.replace(".", "/");
				Enumeration<URL> allResources = classLoader.getResources(packageName);
				while (allResources.hasMoreElements()) {
					URL url = allResources.nextElement();
					log.debug("Full URL for this package: " + url.getPath());
					url = new URL(url.getPath().substring(0, url.getPath().length() - packageName.length() - "!/".length()));
					log.debug("Base URL for the JAR: " + url.getPath());
					jarFileList.add(new File(URLDecoder.decode(url.getPath(), "UTF-8")));
				}
				
			}
			for (File candidateJarFile : jarFileList) {
				log.debug("Processing JAR: " + candidateJarFile.getName());
				JarFile jarFile = new JarFile(candidateJarFile);
				Enumeration<JarEntry> jarEntries = jarFile.entries();
				while (jarEntries.hasMoreElements()) {
					JarEntry jarEntry = jarEntries.nextElement();
					if (!jarEntry.getName().startsWith(packageName) ||!jarEntry.getName().endsWith(".class")) {
						continue;
					}
					//log.debug(" class: " + jarEntry.getName());
					try {
						Class<?> currentClass = Class.forName(jarEntry.getName().replace("/", ".").substring(0, jarEntry.getName().length()-".class".length()));
						if (Modifier.isAbstract(currentClass.getModifiers())) {
							continue;	// Don't include abstract classes
						}
						for (Class<?> currentInterfaceClass : currentClass.getInterfaces()) {
							//log.debug(" Class " + currentClass.getName() + " implements: " + currentInterfaceClass.getName());
							if (currentInterfaceClass.getName().equals(interfaceClass.getName())) {
								implementationList.add(currentClass);
								break;
							}
						}
						if (checkSuperClasses) {
							Class superClass = currentClass;
							boolean foundMatch = false;
							while (!foundMatch && !((superClass = superClass.getSuperclass())==null || superClass.getName().startsWith("java.") || superClass.getName().startsWith("javax."))) {
								for (Class<?> currentInterfaceClass : superClass.getInterfaces()) {
									//log.debug(" SuperClass: " + superClass.getName() + " of " + currentClass.getName() + " implements: " + currentInterfaceClass.getName());
									if (currentInterfaceClass.getName().equals(interfaceClass.getName())) {
										implementationList.add(currentClass);
										foundMatch = true;
										break;
									}
								}
							}
						}
					} catch (UnsatisfiedLinkError e) {
						log.warn("Could not load dependency for this class.. skipping this JAR. (UnsatisfiedLinkError: " + e.getMessage() + ")");
						break;	// If we fail to load the class then this JAR wasn't in the class-path, so skip it.
					} catch (NoClassDefFoundError e) {
						log.warn("Could not load dependency for this class.. skipping this JAR. (NoClassDefFoundError: " + e.getMessage() + ")");
						break;	// If we fail to load the class then this JAR wasn't in the class-path, so skip it.
					} catch (ClassNotFoundException e) {
						log.warn("Could not load class.. skipping this JAR. (ClassNotFoundException: "  + e.getMessage() + ")");
						break;	// If we fail to load the class then this JAR wasn't in the class-path, so skip it.
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		log.trace("<getSome took "+ (new Date().getTime()-start) + " ms");
		return implementationList;
	}
	
	/**
	 * Recursive method to include JAR files from sub directories.
	 */
	private static void addJarsFromDir(File directory, List<File> jarFileList) {
		if (directory.isDirectory()) {
			if (log.isDebugEnabled()) {
				log.debug("Processing directory: " + directory.getName());
			}
			for (File file : directory.listFiles()) {
				if (file.isDirectory()) {
					addJarsFromDir(file, jarFileList);
				} else if (file.getName().endsWith(".jar")) {
					jarFileList.add(file);
				}
			}
		}
	}
}
