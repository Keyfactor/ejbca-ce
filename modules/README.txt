The EJBCA build system
----------------------
This directory contains/will contain all the different modules that is required to build EJBCA and
the stand alone VA. All modules will not always be built, depending on the configuration.

You should be able to build and to run any modules JUnit tests any module separately. Dependencies
should be built automatically.

Different modules and build-scripts
-----------------------------------
Moving different parts of EJBCA to well-defined modules is still an on-going process.

modules/build.xml
  The main build file where all ant-targets from different modules that are used outside the modules
  are defined. This file is included from all modules/{module name}/build.xml.  
modules/build-properties.xml
  Paths, class-paths and variables are defined here. Included from modules/build.xml.
modules/build-helpers.xml
  Contains general ant-targets that are used from several modules. Included from modules/build.xml.
modules/{module-name}/build.xml
  The modules build file. Should normally have at least a "build" and "test" target.
  This is where dependencies on other modules are managed.
modules/dist/
  This is a directory that hold results (JAR, WAR files) from the different module builds that
  should be re-used by different modules.
dist/
  This is a directory that hold results (EAR, DataSources, CLI files) that are deployable or can
  be used directly by the one installing EJBCA. 
modules/common/
  This directory holds (/will hold) common libraries and meta-data used by the different modules.
build.xml
  Contains all the targets that are of concern to the one installing/upgrading/testing EJBCA.
src/
  Still contains the main source-code of EJBCA and some meta-data used for deployment.
  
Creating a new module
---------------------
This is just a general guideline that has to be adapted for each module.
- Create a new directory modules/{module-name}.
- Create new sub-directories
modules/{module-name}/src         Holds the module's source-code
modules/{module-name}/src-test    Holds the module's JUnit test source-code
modules/{module-name}/resources   Holds the module's meta-data and templates
- Create a new build script, modules/{module-name}/build.xml using the following template:

<?xml version="1.0" encoding="UTF-8"?>
<project name="{module-name}" default="build">
    <description>
    	Describe the module here...
    </description>

	<dirname property="module-name.dir" file="${ant.file.{module-name}}"/>

	<import file="${module-name.dir}/../build-helpers.xml"/>
	
	<property name="module-name.build.dir" location="${module-name.dir}/build"/>
	<property name="module-name.build-test.dir" location="${module-name.dir}/build-test"/>
	<property name="module-name.src.dir" location="${module-name.dir}/src"/>

	<path id="compile.classpath">
		<path refid="{reference to class-path(s) defined in build-properties.xml}"/>
		...
	</path>
	
	<path id="compile-test.classpath">
		<path refid="compile.classpath"/>
		<path refid="lib.junit.classpath"/>
		<path location="${mod.module-name.lib}"/>
	</path>
	
	<path id="test.classpath">
		<path location="${module-name.build-test.dir}" />
		<path refid="compile-test.classpath"/>
	</path>

    <target name="build" description="Build this module" depends="compile">
    	<jar ...
    	</jar>
    </target>

    <target name="clean" description="Clean up this module">
		<delete dir="${module-name.build.dir}" />
		<delete dir="${module-name.build-test.dir}" />
		<delete file="{JAR produced by 'build'}" />
    </target>
	
    <target name="compile">
       	<mkdir dir="${module-name.build.dir}" />
        <javac srcdir="${module-name.src.dir}" destdir="${module-name.build.dir}" debug="on" includeantruntime="no" encoding="iso8859-1" target="${java.target.version}"
            classpathref="compile.classpath"/>
    </target>

    <target name="compile-tests">
    	<mkdir dir="${module-name.build-test.dir}" />
        <javac srcdir="${src-test.dir}" destdir="${module-name.build-test.dir}" debug="on" includeantruntime="no" encoding="iso8859-1" target="${java.target.version}"
            classpathref="compile-test.classpath"/>
        <copy file="${log4j.test.file}" tofile="${module-name.build-test.dir}/log4j.xml" failonerror="true"/>
    </target>

	<target name="test" depends="compile-tests" description="Run tests for this module">
    	<antcall target="showtime" inheritall="true" inheritrefs="true"/>
		<junit printsummary="yes" haltonfailure="no" showoutput="${test.showoutput}" dir="${module-name.dir}">
			<classpath>
        		<path refid="test.classpath"/>
        		<path refid="lib.clover.classpath"/>
			</classpath>
			<formatter type="xml" />
			<batchtest fork="yes" todir="${reports.dir}">
				<fileset dir="${module-name.build-test.dir}" includes="**/*Test.class">
					...
				</fileset>
			</batchtest>
		</junit>
		<antcall target="createreport" inheritall="true" inheritrefs="true"/>
    	<antcall target="showtime" inheritall="true" inheritrefs="true"/>
    </target>

	<target name="runone" depends="compile-tests">
		<fail message="'test.runone' is not set. Example -Dtest.runone=NameOfTest . You can also use -Dtest.showoutput=true to send test output to console." unless="test.runone" />
		<junit printsummary="yes" haltonfailure="no" >
			<classpath>
        		<path refid="test.classpath"/>
			</classpath>
			<formatter type="xml" />
			<batchtest fork="yes" todir="${reports.dir}">
				<fileset dir="${module-name.build-test.dir}">
					<include name="**/${test.runone}.class" />
				</fileset>
			</batchtest>
		</junit>
		<antcall target="createreport" inheritall="true" inheritrefs="true"/>
	</target>
</project>

