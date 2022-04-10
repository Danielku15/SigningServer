import java.nio.file.Paths

fun main(args: Array<String>) {
    if (args.size != 3) {
        println("Usage: apksig-transpiler PathToGitRepo PathToMainOutputs PathToTestOutputs")
        return
    }

    val apkSigRepo = args[0]
    val apkSignerPath = Paths.get(apkSigRepo, "src", "main", "java", "com", "android", "apksig", "ApkSigner.java")
    if (!apkSignerPath.toFile().exists()) {
        println("Could not find ApkSigner.java at $apkSignerPath")
        return
    }

    val mainSources = Paths.get(apkSigRepo, "src", "main", "java")
    val mainTranspiler = JavaToCsharpTranspiler(Paths.get(args[1]), mainSources)
    mainTranspiler.transpile()
}