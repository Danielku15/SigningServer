import com.github.javaparser.ParseResult
import com.github.javaparser.ast.CompilationUnit
import com.github.javaparser.symbolsolver.JavaSymbolSolver
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver
import com.github.javaparser.utils.Log
import com.github.javaparser.utils.SourceRoot
import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import kotlin.io.path.absolutePathString


class JavaToCsharpTranspiler(
    private val output: Path,
    private val sources: Path,
    private vararg val additionalSources: Path
) {
    var overallBaseTypeName: String? = null

    fun transpile() {
//        Log.setAdapter(Log.StandardOutStandardErrorAdapter())

        val sourcesParsed = parseSources()

        var successful = true;
        for (source in sourcesParsed.second.entries) {
            val problems = source.value.problems
            if (problems.isNotEmpty()) {
                println("Problems with file ${source.key}")
                for (problem in problems) {
                    println(problem.verboseMessage)
                }
            }

            if (!source.value.isSuccessful) {
                successful = false
            }
        }

        if (!successful) {
            throw kotlin.IllegalStateException("Failed to parse sources")
        }

        val context = CSharpEmitterContext()
        context.overallBaseTypeName = overallBaseTypeName
        println("Transforming to C# AST");
        for (source in sourcesParsed.second.entries) {
            println("  Transforming ${source.key}")
            val transformer = CSharpAstTransformer(sources, output, source.key, source.value.result.get(), context);
            transformer.transform()
        }

        println("Resolving types");
        context.resolveAllUnresolvedTypeNodes();
        context.rewriteVisibilities();

        if (!context.hasErrors) {
            println("Writing Result");
            for (file in context.csharpFiles) {
                val printer = CSharpAstPrinter(file, context)
                printer.print()
            }
        }

        for (problem in context.problems) {
            println(problem.verboseMessage)
        }
    }

    private fun parseSources(): Pair<JavaSymbolSolver, Map<Path, ParseResult<CompilationUnit>>> {

        val typeSolver = CombinedTypeSolver(ReflectionTypeSolver(), CombinedTypeSolver(), JavaParserTypeSolver(sources))
        for (additional in additionalSources) {
            typeSolver.add(JavaParserTypeSolver(additional))
        }

        val sourceRoot = SourceRoot(sources)
        val symbolSolver = JavaSymbolSolver(typeSolver)
        sourceRoot.parserConfiguration.setSymbolResolver(symbolSolver)

        println("Parsing sources")
        val sourcesParsed = HashMap<Path, ParseResult<CompilationUnit>>()
        Files.walkFileTree(sources, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (!attrs.isDirectory && file.toString().endsWith(".java")) {
                    val relative = sources.relativize(file.parent)
                    val result = sourceRoot.tryToParse(relative.toString(), file.fileName.toString())
                    println("  Parsing ${file.absolutePathString()}")
                    sourcesParsed[file] = result
                }
                return FileVisitResult.CONTINUE
            }

            @Throws(IOException::class)
            override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                return FileVisitResult.CONTINUE
            }
        })

        return Pair(symbolSolver, sourcesParsed)
    }
}