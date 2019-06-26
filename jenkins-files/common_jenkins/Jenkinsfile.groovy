def copyCommonScripts() {
    println("copyCommonScripts")
}

def get_ANT_OPTS() {
    return "-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx1024m"
}

def get_TEST_OPTS() {
    return "-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx256m"
}

def copy_cesecore() {
    println(" " + pwd())
    return "echo 'A'"
}

return this