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

package org.ejbca.repository.generator;

import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.nio.file.Files;
import java.util.TimeZone;
import java.util.stream.Stream;

public class Main {

    private static void delete(File file) {
        if (file.exists()) {
            if (file.isDirectory()) {
                for (File child : file.listFiles()) {
                    delete(child);
                }
            }
            file.delete();
        }
    }

    private static File getDir(File outputDir, String packageName) {
        return new File(outputDir, packageName.replaceAll("\\.", File.separator));
    }

    private static String firstUpperCase(String s) {
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    private static void doGenerateFile(Configuration configuration, File dir, String templateName, Entity entity, boolean force) throws Exception {
        String filename = templateName
                .replace("dto", firstUpperCase(entity.getName()))
                .replace("ftl", "java");
        File file = new File(dir, filename);
        if (force || !file.exists()) {
            file.getParentFile().mkdirs();
            Writer out = new FileWriter(file);
            configuration.getTemplate(templateName).process(entity, out);
        }
    }

    private static String getSrcDirName(final boolean test, final String templateName) {
        if (test) {
            return "modules/ejbca-repository/src-test";
        }
        else {
            if (templateName.contains("Dto")) {
                return "modules/cesecore-entity/src";
            }
            else {
                return "modules/ejbca-entity/src";
            }
        }
    }

    private static void generateFiles(Configuration configuration, File rootDir, boolean test, String[] templateNames, Entity entity, boolean force) throws Exception {
        for (String templateName : templateNames) {
            File srcDir = new File(rootDir, getSrcDirName(test, templateName));
            if (test || templateName.contains("Dto")) {
                entity.setPackageName("org.cesecore");
            }
            else {
                entity.setPackageName("org.ejbca");
            }
            File dir = getDir(srcDir, entity.getPackageName()+".dto");
            doGenerateFile(configuration, dir, templateName, entity, force);
        }
    }

    private static Configuration getTemplateConfiguration(File templateDir) throws Exception {
        Configuration configuration = new Configuration(Configuration.VERSION_2_3_34);
        configuration.setDirectoryForTemplateLoading(templateDir);
        // Recommended settings for new projects:
        configuration.setDefaultEncoding("UTF-8");
        configuration.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        configuration.setLogTemplateExceptions(false);
        configuration.setWrapUncheckedExceptions(true);
        configuration.setFallbackOnNullLoopVariable(false);
        configuration.setSQLDateAndTimeTimeZone(TimeZone.getDefault());
        configuration.setAPIBuiltinEnabled(true);
        return configuration;
    }

    public static File deleteAndCreateEmptyDir(String dirName) {
        File dir = new File(dirName);
        delete(dir);
        dir.mkdirs();
        return dir;
    }

    public static FileInputStream getFileInputStream(File file) throws Exception {
        if (!file.isFile()) {
            throw new IllegalArgumentException("Argument " + file.getCanonicalPath() + " is not a file");
        }
        return new FileInputStream(file);
    }

    private static boolean isRootDir(File dir) {
        return Stream.of(dir.listFiles())
                .map(File::getName)
                .anyMatch(name->"settings.gradle.kts".equals(name));
    }

    private static File getRootDir(File outputDir) {
        if (outputDir == null) {
            throw new IllegalArgumentException("Argument " + outputDir + " is null");
        }
        return isRootDir(outputDir) ?
                outputDir :
                getRootDir(outputDir.getParentFile());
    }

    private static File getRootDir() throws IOException {
        return getRootDir(new File(".").getCanonicalFile());
    }

    private static Entity parseJson(final String dtoName, final InputStream inputStream, boolean test) {
        Entity entity = JsonUtil.parseJson(inputStream, Entity.class);
        entity.setName(dtoName);
        entity.setTest(test);
        if (entity.getIndexNames() == null) {
            entity.setIndexNames(new String[0]);
        }
        return entity;
    }

    private static void updateOrmMappingFile(final File file, final Entity entity) throws IOException {
        final var content = Files.readString(file.toPath()).replace(
                "org.cesecore.certificates.ca."+entity.getName(),
                entity.getPackageName()+".dto."+entity.getName());
        Files.write(file.toPath(), content.getBytes());
    }

    private static void updateOrmMappingFiles(final File rootDir, final Entity entity) throws IOException {
        final var dir = new File(rootDir, "modules/ejbca-entity/resources");
        final var files = dir.listFiles(file ->
                file.getName().startsWith("orm-ejbca") && file.getName().endsWith(".xml"));
        for (File file : files) {
            updateOrmMappingFile(file, entity);
        }
    }

    private static void doMain(File rootDir, boolean test, String entityName, boolean force) throws Exception {
        final String nameSuffix = test ? "-test" : "";
        final File templatesDir = new File(rootDir, "modules/ejbca-repository/templates");
        final String[] templateNames = templatesDir.list();
        final String jsonFileName = "modules/ejbca-repository/resources" + nameSuffix + "/" + entityName + ".json";
        final File jsonFile = new File(rootDir, jsonFileName);
        if (!jsonFile.isFile()) {
            throw new IllegalArgumentException("Cannot find the file: " + jsonFile.getCanonicalPath());
        }
        Configuration configuration = getTemplateConfiguration(templatesDir);
        try (FileInputStream fileInputStream = getFileInputStream(jsonFile)) {
            final var name = jsonFile.getName().replace(".json", "");
            final var entity = parseJson(name, fileInputStream, test);
            generateFiles(configuration, rootDir, test, templateNames, entity, force);
            if (!test) {
                updateOrmMappingFiles(rootDir, entity);
            }
        }
    }

    private static boolean isArgument(final String[] args, final String name) {
        for (String arg : args) {
            if (arg.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static String getArgument(final String[] args, final String name) throws Exception{
        for (int i = 0; i < args.length-1; i++) {
            if (args[i].equals(name)) {
                return args[i+1];
            }
        }
        throw new Exception("Argument " + name + " not found");
    }

    public static void main(String[] args) throws Exception {
        final String entityName = getArgument(args, "--entityName");
        final boolean test = isArgument(args, "--test");
        final boolean force = isArgument(args, "--force");
        final var rootDir = getRootDir();
        try {
            doMain(rootDir, test, entityName, force);
        }
        catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

}
