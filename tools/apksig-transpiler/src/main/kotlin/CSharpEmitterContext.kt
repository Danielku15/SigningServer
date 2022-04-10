import com.github.javaparser.Problem
import com.github.javaparser.ast.body.RecordDeclaration
import com.github.javaparser.ast.expr.Name
import com.github.javaparser.resolution.declarations.ResolvedTypeDeclaration
import com.github.javaparser.resolution.types.ResolvedArrayType
import com.github.javaparser.resolution.types.ResolvedPrimitiveType
import com.github.javaparser.resolution.types.ResolvedReferenceType
import com.github.javaparser.resolution.types.ResolvedType
import com.github.javaparser.symbolsolver.JavaSymbolSolver

class CSharpEmitterContext(public val symbolSolver: JavaSymbolSolver) {
    private val unresolvedTypeNodes: MutableList<CsUnresolvedTypeNode> = ArrayList()
    val problems: MutableList<Problem> = ArrayList()
    val csharpFiles: MutableList<CsSourceFile> = ArrayList()
    var hasErrors: Boolean = false

    fun resolveAllUnresolvedTypeNodes() {
        for (node in this.unresolvedTypeNodes) {
            val resolved = this.resolveType(node);
            if (!resolved) {
                this.addCsNodeDiagnostics(node, "Could not resolve type", true);
            }
        }
    }

    private fun resolveType(node: CsUnresolvedTypeNode): Boolean {
        if (node.jDeclaration != null) {
            if (node.jDeclaration!!.isType) {
                val resolvedType = (node.jDeclaration as ResolvedTypeDeclaration)
                val key = getSymbolKey(resolvedType)
                if (symbolLookup.containsKey(key)) {
                    node.resolved = CsTypeReference(symbolLookup[key] as CsNamedTypeDeclaration)
                    node.resolved!!.parent = node.parent
                    return true
                } else {
                    val csName = mapKnownTypes(toPascalCase(resolvedType.qualifiedName))
                    node.resolved = CsTypeReference(CsStringTypeReference(csName))
                    node.resolved!!.parent = node.parent
                    return true
                }
            }
        }

        if (node.jType != null) {
            node.resolved = this.resolveType(node.parent, node.jType!!)

        }

        return node.resolved != null
    }

    fun resolveType(parent: CsNode?, s: ResolvedType): CsTypeNode? {
        return if (s.isPrimitive) {
            val p = s as ResolvedPrimitiveType
            val csp = when (p) {
                ResolvedPrimitiveType.BYTE -> CsPrimitiveTypeNode(CsPrimitiveType.Byte)
                ResolvedPrimitiveType.SHORT -> CsPrimitiveTypeNode(CsPrimitiveType.Short)
                ResolvedPrimitiveType.CHAR -> CsPrimitiveTypeNode(CsPrimitiveType.Char)
                ResolvedPrimitiveType.INT -> CsPrimitiveTypeNode(CsPrimitiveType.Int)
                ResolvedPrimitiveType.LONG -> CsPrimitiveTypeNode(CsPrimitiveType.Long)
                ResolvedPrimitiveType.BOOLEAN -> CsPrimitiveTypeNode(CsPrimitiveType.Bool)
                ResolvedPrimitiveType.FLOAT -> CsPrimitiveTypeNode(CsPrimitiveType.Float)
                ResolvedPrimitiveType.DOUBLE -> CsPrimitiveTypeNode(CsPrimitiveType.Double)
            }
            csp.parent = parent
            csp
        } else if (s.isArray) {
            val array = s as ResolvedArrayType
            val elementType = resolveType(null, array.componentType) ?: return null
            val csa = CsArrayTypeNode(
                elementType
            )
            csa.parent = parent
            csa
        } else if (s.isVoid) {
            val csp = CsPrimitiveTypeNode(CsPrimitiveType.Void)
            csp.parent = parent
            csp
        } else if (s.isReference) {
            val r = s as ResolvedReferenceType
            val key = getSymbolKey(r)
            if (symbolLookup.containsKey(key)) {
                val ref = CsTypeReference(symbolLookup[key] as CsNamedTypeDeclaration)
                ref.parent = parent
                ref.typeArguments = r.typeParametersMap.map { resolveType(ref, it.b)!! }.toMutableList()
                ref
            } else {
                val csName = mapKnownTypes(toPascalCase(r.qualifiedName))
                val ref = CsTypeReference(CsStringTypeReference(csName))
                ref.typeArguments = r.typeParametersMap.map { resolveType(ref, it.b)!! }.toMutableList()
                ref.parent = parent
                ref
            }
        } else {
            null
        }
    }

    fun mapKnownTypes(s: String): String {
        return when (s) {
            "Java.Lang.Exception" -> "System.Exception"
            "Java.Lang.Throwable" -> "System.Exception"
            "Java.Util.Comparator" -> "System.Collections.Generic.IComparer"
            "Java.Io.Closeable" -> "System.IDisposable"
            "Java.Io.InputStream" -> "SigningServer.Android.InputStream"
            else -> s
        }
    }

    fun getSymbolName(expr: CsExpression): String? {
        return null;
    }

    fun addCsNodeDiagnostics(expr: CsNode, text: String, b: Boolean) {

    }

    fun addJNodeDiagnostics(declaration: RecordDeclaration, s: String, b: Boolean) {
    }

    fun getFullName(type: CsNamedTypeDeclaration, expr: CsNode? = null): String {
        if (type.parent == null) {
            return "";
        }
        return when (type.parent!!.nodeType) {
            CsSyntaxKind.ClassDeclaration, CsSyntaxKind.InterfaceDeclaration, CsSyntaxKind.EnumDeclaration ->
                this.getFullName(type.parent as CsNamedTypeDeclaration) + "." + this.getClassName(type, expr);
            CsSyntaxKind.NamespaceDeclaration ->
                (type.parent as CsNamespaceDeclaration).namespace + '.' + this.getClassName(type, expr);
            else -> ""
        }
    }

    private fun getClassName(type: CsNamedTypeDeclaration, expr: CsNode?): Any? {
        return type.name
    }

    fun isConst(d: CsFieldDeclaration): Boolean {
        return false
    }

    fun getFullName(type: Name?): String {
        if (type == null) {
            return ""
        }

        val sb = StringBuilder()
        if (type.qualifier.isPresent) {
            sb.append(getFullName(type.qualifier.get()))
            sb.append(".")
        }
        sb.append(toPascalCase(type.identifier))
        return sb.toString()
    }

    private fun toPascalCase(identifier: String?): String {
        if (identifier == null) {
            return ""
        }

        return identifier.split(".").map { it.substring(0, 1).uppercase() + it.substring(1) }.joinToString(".");
    }

    private val symbolLookup: MutableMap<String, CsNode> = HashMap()

    fun registerSymbol(d: CsNamedTypeDeclaration) {
        val symbolKey = this.getSymbolKey(d);
        this.symbolLookup[symbolKey] = d
    }

    private fun getSymbolKey(d: CsNamedTypeDeclaration): String {
        return getSymbolKey(d.jSymbol as ResolvedTypeDeclaration)
    }

    private fun getSymbolKey(d: ResolvedReferenceType): String {
        return d.qualifiedName
    }

    private fun getSymbolKey(d: ResolvedTypeDeclaration): String {
        return d.qualifiedName
    }

    private fun getSymbolKey(d: CsEnumMember): String {
        return getSymbolKey(d.parent as CsEnumDeclaration) + "." + d.name
    }

    fun registerSymbol(d: CsEnumMember) {
        val symbolKey = this.getSymbolKey(d);
        this.symbolLookup[symbolKey] = d
    }

    fun toPropertyName(first: String): String {
        return toPascalCase(first)
    }

    fun toMethodName(nameAsString: String?): String {
        return toPascalCase((nameAsString))
    }

    fun registerUnresolvedTypeNode(node: CsUnresolvedTypeNode) {
        this.unresolvedTypeNodes.add(node);
    }

    fun toFieldName(name: String): String {
        return name
    }
}