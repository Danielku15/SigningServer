import com.github.javaparser.Problem
import com.github.javaparser.ast.body.RecordDeclaration
import com.github.javaparser.ast.expr.Name
import com.github.javaparser.resolution.declarations.ResolvedFieldDeclaration
import com.github.javaparser.resolution.declarations.ResolvedTypeDeclaration
import com.github.javaparser.resolution.types.ResolvedArrayType
import com.github.javaparser.resolution.types.ResolvedPrimitiveType
import com.github.javaparser.resolution.types.ResolvedReferenceType
import com.github.javaparser.resolution.types.ResolvedType
import com.github.javaparser.symbolsolver.JavaSymbolSolver

class CSharpEmitterContext() {
    var overallBaseTypeName: String? = null
    private val unresolvedTypeNodes: MutableList<CsUnresolvedTypeNode> = ArrayList()
    private val symbolConst: MutableSet<String> = HashSet()
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
        if (node.resolved != null) {
            return true
        }

        if (node.jDeclaration != null) {
            if (node.jDeclaration!!.isType) {
                val resolvedType = (node.jDeclaration as ResolvedTypeDeclaration)
                val key = getSymbolKey(resolvedType)
                if (symbolLookup.containsKey(key)) {
                    node.resolved = CsTypeReference(symbolLookup[key] as CsNamedTypeDeclaration).apply {
                        this.typeArguments = node.typeArguments
                    }
                    node.resolved!!.parent = node.parent
                    return true
                } else {
                    val csName = mapKnownTypes(toPascalCase(resolvedType.qualifiedName))
                    val special = handleSpecialName(node.parent, csName)
                    if (special != null) {
                        node.resolved = special
                    } else {
                        node.resolved = CsTypeReference(CsStringTypeReference(csName)).apply {
                            this.typeArguments = node.typeArguments
                        }
                        node.resolved!!.parent = node.parent
                    }
                    return true
                }
            }
        }

        if (node.jType != null) {
            node.resolved = this.resolveType(
                node.parent,
                node.jType!!,
                node.typeArguments.ifEmpty { null }
            )
            return true
        }

        if(node.jNode != null) {
            if(node.jNode is Name) {
                node.resolved = CsTypeReference(
                    CsStringTypeReference((node.jNode as Name).asString())
                )
                node.resolved!!.parent = node.parent
                return true
            }
            return true;
        }

        return node.resolved != null
    }

    fun resolveType(parent: CsNode?, s: ResolvedType, typeArguments: MutableList<CsTypeNode>?): CsTypeNode? {
        return if (s.isPrimitive) {
            val p = s as ResolvedPrimitiveType
            val csp = when (p) {
                ResolvedPrimitiveType.BYTE -> CsPrimitiveTypeNode(CsPrimitiveType.SByte)
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
            val elementType = resolveType(null, array.componentType, null) ?: return null
            val csa = CsArrayTypeNode(
                elementType
            )
            csa.parent = parent
            csa
        } else if (s.isVoid) {
            val csp = CsPrimitiveTypeNode(CsPrimitiveType.Void)
            csp.parent = parent
            csp
        } else if (s.isTypeVariable) {
            val csp = CsTypeReference(
                CsStringTypeReference((s.asTypeVariable().asTypeParameter().name))
            )
            csp.parent = parent
            csp
        } else if (s.isWildcard) {
            val wc = s.asWildcard()
            if (wc.isBounded) {
                resolveType(parent, s.asWildcard().boundedType, null)
            } else {
                val csp = CsPrimitiveTypeNode(CsPrimitiveType.Object)
                csp.parent = parent
                csp
            }
        } else if (s.isUnionType) {
            val csp = CsPrimitiveTypeNode(CsPrimitiveType.Object)
            csp.parent = parent
            csp
        } else if(s.isNull) {
            val csp = CsPrimitiveTypeNode(CsPrimitiveType.Object)
            csp.parent = parent
            csp
        } else if (s.isReference) {

            val r = s as ResolvedReferenceType
            val key = getSymbolKey(r)
            if (symbolLookup.containsKey(key)) {
                val ref = CsTypeReference(symbolLookup[key] as CsNamedTypeDeclaration)
                ref.parent = parent
                if (typeArguments == null) {
                    ref.typeArguments = r.typeParametersMap.map { resolveType(ref, it.b, null)!! }.toMutableList()
                } else {
                    ref.typeArguments = typeArguments
                }
                ref
            } else {
                val csName = mapKnownTypes(toPascalCase(r.qualifiedName))
                val special = handleSpecialName(parent, csName)
                if (special != null) {
                    special
                } else {
                    val ref = CsTypeReference(CsStringTypeReference(csName))
                    if (typeArguments == null) {
                        ref.typeArguments =
                            r.typeParametersMap.map { resolveType(ref, it.b, null)!! }.toMutableList()
                    } else {
                        ref.typeArguments = typeArguments
                    }
                    ref.parent = parent
                    ref
                }
            }
        } else {
            null
        }
    }

    private fun handleSpecialName(parent: CsNode?, csName: String): CsTypeNode? {
        return when (csName) {
            "sbyte?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.SByte)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "short?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Short)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "int?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Int)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "long?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Long)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "float?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Float)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "double?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Double)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "bool?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Bool)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "char?" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Char)
                ref.isNullable = true
                ref.parent = parent
                ref
            }
            "string" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.String)
                ref.parent = parent
                ref
            }
            "object" -> {
                val ref = CsPrimitiveTypeNode(CsPrimitiveType.Object)
                ref.parent = parent
                ref
            }
            else -> {
                null
            }
        }
    }

    fun mapKnownTypes(s: String): String {
        return when (s) {
            "Java.Lang.Exception" -> "System.Exception"
            "Java.Lang.Throwable" -> "System.Exception"
            "Java.Util.Comparator" -> "System.Collections.Generic.IComparer"
            "Java.Io.Closeable" -> "System.IDisposable"
            "Java.Lang.AutoCloseable" -> "System.IDisposable"
            "Java.Lang.String" -> "string"
            "Java.Io.File" -> "System.IO.FileInfo"
            "Java.Util.Map.Entry" -> "SigningServer.Android.Collections.MapEntry"
            "Java.Util.Map" -> "SigningServer.Android.Collections.Map"
            "Java.Util.Set" -> "SigningServer.Android.Collections.Set"
            "Java.Util.List" -> "SigningServer.Android.Collections.List"
            "Java.Util.Collection" -> "SigningServer.Android.Collections.Collection"
            "Java.Util.ArrayList" -> "SigningServer.Android.Collections.List"
            "Java.Util.Arrays" -> "SigningServer.Android.Collections.Arrays"
            "Java.Util.HashMap" -> "SigningServer.Android.Collections.HashMap"
            "Java.Util.HashSet" -> "SigningServer.Android.Collections.HashSet"
            "Java.Util.SortedMap" -> "SigningServer.Android.Collections.SortedMap"
            "Java.Util.EnumMap" -> "SigningServer.Android.Collections.EnumMap"
            "Java.Util.TreeMap" -> "SigningServer.Android.Collections.TreeMap"
            "Java.Util.Iterator" -> "SigningServer.Android.Collections.Iterator"
            "Java.Lang.IllegalStateException" -> "System.InvalidOperationException"
            "Java.Lang.IndexOutOfBoundsException" -> "System.IndexOutOfRangeException"
            "Java.Lang.IllegalArgumentException" -> "System.ArgumentException"
            "Java.Lang.UnsupportedOperationException" -> "System.InvalidOperationException"
            "Java.Lang.Obsolete" -> "System.ObsoleteAttribute"
            "Java.Lang.Byte" -> "sbyte?"
            "Java.Lang.Short" -> "short?"
            "Java.Lang.Integer" -> "int?"
            "Java.Lang.Long" -> "long?"
            "Java.Lang.Float" -> "float?"
            "Java.Lang.Double" -> "double?"
            "Java.Lang.Boolean" -> "bool?"
            "Java.Lang.Character" -> "char?"
            "Java.Lang.Object" -> "object"
            "Java.Lang.NullPointerException" -> "System.NullReferenceException"
            else -> {
                val mappings = arrayOf(
                    Pair("Java.Lang.", "SigningServer.Android.Core."),
                    Pair("Java.Io.", "SigningServer.Android.IO."),
                    Pair("Java.Nio.", "SigningServer.Android.IO."),
                    Pair("Java.", "SigningServer.Android."),
                )
                var ns = s
                loop@ for (x in mappings) {
                    if (ns.startsWith(x.first)) {
                        ns = x.second + ns.substring(x.first.length)
                        break@loop
                    }
                }
                ns
            }
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

    public fun isConst(declaration: CsFieldDeclaration): Boolean {
        val symbolKey = this.getSymbolKey(declaration);
        return this.symbolConst.contains(symbolKey)
    }

    public fun registerSymbolAsConst(symbol: ResolvedFieldDeclaration) {
        val symbolKey = this.getSymbolKey(symbol);
        this.symbolConst.add(symbolKey);
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

    private fun getSymbolKey(d: CsFieldDeclaration): String {
        return getSymbolKey(d.parent as CsClassDeclaration) + "." + d.name
    }

    private fun getSymbolKey(d: ResolvedFieldDeclaration): String {
        return getSymbolKey(d.declaringType()) + "." + d.name
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
        var name = toPascalCase((nameAsString))

        when (name) {
            "HashCode" -> name = "GetHashCode"
            "GetClass" -> name = "GetType"
        }

        return name
    }

    fun registerUnresolvedTypeNode(node: CsUnresolvedTypeNode) {
        this.unresolvedTypeNodes.add(node);
    }

    fun toFieldName(name: String): String {
        return toLocalVariable(name)
    }

    fun toLocalVariable(name: String): String {
        return when (name) {
            "in" -> "input"
            "out" -> "output"
            "params" -> "parameters"
            else -> name
        }
    }

    fun toParameterName(name: String): String {
        return toLocalVariable(name)
    }

    fun rewriteVisibilities() {
        for (f in this.csharpFiles) {
            for (t in f.namespace!!.declarations) {
                if (t is CsClassDeclaration) {
                    makeMembersInternal(t)
                } else if (t is CsInterfaceDeclaration) {
                    makeMembersInternal(t)
                }
            }
        }
    }

    private fun makeMembersInternal(n: CsClassDeclaration) {
        if (n.visibility == CsVisibility.Private) {
            n.visibility = CsVisibility.Internal
        }

        for (m in n.members) {
            when (m) {
                is CsConstructorDeclaration -> if (m.visibility == CsVisibility.Private) {
                    m.visibility = CsVisibility.Internal
                }
                is CsMethodDeclaration -> if (m.visibility == CsVisibility.Private) {
                    m.visibility = CsVisibility.Internal
                }
                is CsFieldDeclaration -> if (m.visibility == CsVisibility.Private) {
                    m.visibility = CsVisibility.Internal
                }
                is CsClassDeclaration -> makeMembersInternal(m)
                is CsInterfaceDeclaration -> makeMembersInternal(m)
            }
        }
    }

    private fun makeMembersInternal(n: CsInterfaceDeclaration) {
        if (n.visibility == CsVisibility.Private) {
            n.visibility = CsVisibility.Internal
        }

        for (m in n.members) {
            when (m) {
                is CsClassDeclaration -> makeMembersInternal(m)
                is CsInterfaceDeclaration -> makeMembersInternal(m)
            }
        }
    }
}