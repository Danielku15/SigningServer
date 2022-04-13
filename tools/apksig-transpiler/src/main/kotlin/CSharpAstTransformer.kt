import com.github.javaparser.ast.*
import com.github.javaparser.ast.body.*
import com.github.javaparser.ast.comments.JavadocComment
import com.github.javaparser.ast.expr.*
import com.github.javaparser.ast.stmt.*
import com.github.javaparser.ast.type.Type
import com.github.javaparser.ast.type.TypeParameter
import com.github.javaparser.ast.type.UnionType
import com.github.javaparser.resolution.declarations.ResolvedDeclaration
import com.github.javaparser.resolution.declarations.ResolvedEnumConstantDeclaration
import com.github.javaparser.resolution.declarations.ResolvedFieldDeclaration
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration
import com.github.javaparser.resolution.types.ResolvedReferenceType
import com.github.javaparser.resolution.types.ResolvedType
import java.nio.file.Path
import java.nio.file.Paths
import java.util.*
import kotlin.io.path.absolutePathString
import kotlin.io.path.nameWithoutExtension

class CSharpAstTransformer(
    private val rootPath: Path,
    private val outputPath: Path,
    private val sourceFile: Path,
    private val compilationUnit: CompilationUnit,
    private val context: CSharpEmitterContext
) {
    val csharpFile: CsSourceFile

    init {
        val fileName = buildFileName(rootPath.relativize(sourceFile))

        csharpFile = CsSourceFile().apply {
            val sourceFile = this
            this.jNode = compilationUnit;
            this.fileName = Paths.get(outputPath.absolutePathString(), fileName.toString())
            this.usings.add(CsUsingDeclaration().apply {
                namespaceOrTypeName = "System"
                parent = sourceFile
            })
        }
    }

    private fun buildFileName(relativize: Path): Path {
        return Paths.get(relativize.parent.toString(), relativize.fileName.nameWithoutExtension + ".cs")
    }

    fun transform() {
        csharpFile.namespace = visit(csharpFile, compilationUnit.packageDeclaration)

        for (type in compilationUnit.types) {
            visit(csharpFile.namespace!!, type)
        }

        if (csharpFile.namespace!!.declarations.isNotEmpty()) {
            context.csharpFiles.add(csharpFile)
        }
    }

    private fun visit(parent: CsNode, declaration: EnumDeclaration) {
        val t: CsNamedTypeDeclaration
        if (declaration.members.isNotEmpty()) {
            val clz = CsClassDeclaration()
            t = clz
            clz.parent = parent
            clz.name = declaration.nameAsString
            clz.visibility = visit(declaration.accessSpecifier)
            clz.documentation = visitDocumentation(declaration)
            clz.jSymbol = declaration.resolve()
            visitAnnotations(clz, declaration.annotations)

            declaration.entries.forEachIndexed { index, it ->
                val f = CsFieldDeclaration(CsTypeReference(clz))
                f.parent = clz
                f.isStatic = true
                f.isReadonly = true
                f.visibility = CsVisibility.Public
                f.name = it.nameAsString
                f.initializer = CsNewExpression(CsTypeReference(clz)).apply {
                    this.parent = f
                    this.arguments = it.arguments.map { visit(this, it) }.toMutableList()
                    this.arguments.add(CsNumericLiteral(index.toString()))
                }
                clz.members.add(f)

                val fCase = CsFieldDeclaration(CsPrimitiveTypeNode(CsPrimitiveType.Int))
                fCase.parent = clz
                fCase.isConst = true
                fCase.visibility = CsVisibility.Public
                fCase.name = it.nameAsString + "_CASE"
                fCase.initializer = CsNumericLiteral(index.toString())
                clz.members.add(fCase)
            }

            declaration.members.forEach {
                visit(clz, it)
            }

            val caseValue = CsPropertyDeclaration(CsPrimitiveTypeNode(CsPrimitiveType.Int))
            caseValue.parent = clz
            caseValue.name = "Case"
            caseValue.getAccessor = CsPropertyAccessorDeclaration("get", null)
            caseValue.getAccessor!!.parent = caseValue
            clz.members.add(caseValue)

            val constructor = clz.members.find { it.nodeType == CsSyntaxKind.ConstructorDeclaration } as CsConstructorDeclaration?
            if(constructor != null) {
                val p = CsParameterDeclaration()
                p.parent = constructor
                p.name = "caseValue"
                p.type = CsPrimitiveTypeNode(CsPrimitiveType.Int)
                p.type!!.parent = p
                constructor.parameters.add(p)
                (constructor.body as CsBlock).statements.add(CsExpressionStatement(
                    CsBinaryExpression(
                        CsIdentifier(caseValue.name),
                        "=",
                        CsIdentifier(p.name)
                    )
                ))
            }

            val valuesInstance = CsFieldDeclaration(
                CsArrayTypeNode(CsTypeReference(clz))
            )
            valuesInstance.parent = clz
            valuesInstance.name = "_values"
            valuesInstance.visibility = CsVisibility.Private
            valuesInstance.isStatic = true
            valuesInstance.isReadonly = true
            val valuesInstanceInitializer = CsArrayInitializerExpression()
            valuesInstanceInitializer.parent = valuesInstance
            valuesInstanceInitializer.values = declaration.entries.map {
                CsIdentifier(it.nameAsString).apply {
                    this.parent = valuesInstanceInitializer
                }
            }.toMutableList()
            valuesInstance.initializer = valuesInstanceInitializer
            clz.members.add(valuesInstance)

            val valuesMethod = CsMethodDeclaration(CsArrayTypeNode(CsTypeReference(clz)), "Values")
            valuesMethod.parent = clz
            valuesMethod.isStatic = true
            valuesMethod.visibility = CsVisibility.Public
            val valuesMethodBody = CsBlock()
            valuesMethodBody.parent = valuesMethod
            valuesMethodBody.statements.add(
                CsReturnStatement(
                    CsIdentifier(valuesInstance.name)
                )
            )
            valuesMethod.body = valuesMethodBody
            clz.members.add(valuesMethod)
        } else {
            val enum = CsEnumDeclaration()
            t = enum
            enum.name = declaration.nameAsString
            enum.parent = parent
            enum.visibility = visit(declaration.accessSpecifier)
            enum.documentation = visitDocumentation(declaration)
            enum.jSymbol = declaration.resolve()
            visitAnnotations(enum, declaration.annotations)

            declaration.entries.forEach {
                visit(enum, it)
            }
        }

        if (parent is CsNamespaceDeclaration) {
            t.parent = parent
            parent.declarations.add(t)
        } else if (parent is CsClassDeclaration) {
            t.parent = parent
            parent.members.add(t)
        } else if (parent is CsInterfaceDeclaration) {
            t.parent = parent
            parent.members.add(t)
        }
        context.registerSymbol(t)
    }

    private fun visit(enum: CsEnumDeclaration, enumMember: EnumConstantDeclaration) {
        val csEnumMember = CsEnumMember()
        csEnumMember.parent = enum
        csEnumMember.name = enumMember.nameAsString
        csEnumMember.documentation = visitDocumentation(enumMember)
        enum.members.add(csEnumMember)

        context.registerSymbol(csEnumMember)
    }

    private fun visitDocumentation(declaration: Node): String? {
        if (declaration.comment.isPresent && declaration.comment.get().isJavadocComment) {
            // TODO: Full translation
            return (declaration.comment.get() as JavadocComment).parse().toText()
        }
        return null
    }

    private fun visit(accessSpecifier: AccessSpecifier): CsVisibility {
        return when (accessSpecifier) {
            AccessSpecifier.PUBLIC -> CsVisibility.Public
            AccessSpecifier.PACKAGE_PRIVATE -> CsVisibility.Internal
            AccessSpecifier.PRIVATE -> CsVisibility.Private
            AccessSpecifier.PROTECTED -> CsVisibility.Protected
        }
    }

    private fun visit(parent: CsNode, declaration: AnnotationDeclaration) {
        val clz = CsClassDeclaration()
        clz.parent = parent
        clz.name = declaration.nameAsString
        clz.visibility = visit(declaration.accessSpecifier)
        clz.documentation = visitDocumentation(declaration)
        clz.jSymbol = declaration.resolve()

        for (a in declaration.annotations) {
            val ra = a.resolve()
            when (ra.qualifiedName) {
                "java.lang.annotation.Target" ->
                    if (a is SingleMemberAnnotationExpr && a.memberValue is ArrayInitializerExpr) {
                        val au = CsAttribute(CsTypeReference(CsStringTypeReference("System.AttributeUsage")))
                        val flags = (a.memberValue as ArrayInitializerExpr).values.map {
                            if (it.isFieldAccessExpr) {
                                when ((it as FieldAccessExpr).nameAsString) {
                                    "TYPE" -> CsIdentifier("System.AttributeTargets.Class | System.AttributeTargets.Interface")
                                    "METHOD" -> CsIdentifier("System.AttributeTargets.Method")
                                    "PARAMETER" -> CsIdentifier("System.AttributeTargets.Class Parameter")
                                    "CONSTRUCTOR" -> CsIdentifier("System.AttributeTargets.Constructor")
                                    "FIELD" -> CsIdentifier("System.AttributeTargets.Field")
                                    else -> throw IllegalStateException("Unsupported element type")
                                }
                            } else {
                                throw IllegalStateException("Unsupported attribute value")
                            }
                        }.toMutableList()

                        var bitor: CsExpression? = null
                        for (f in flags) {
                            if (bitor == null) {
                                bitor = f
                                bitor.parent = au
                            } else {
                                val old = bitor
                                bitor = CsBinaryExpression(
                                    bitor,
                                    "|",
                                    f
                                )
                                bitor.parent = au
                                old.parent = bitor
                            }
                        }

                        au.indexedArguments.add(bitor!!)
                        clz.attributes.add(au)
                    }
                "java.lang.annotation.Retention" -> {}
            }
        }


        clz.baseClass = CsTypeReference(CsStringTypeReference("System.Attribute"))

        declaration.members.forEach {
            visit(clz, it)
        }

        if (parent is CsNamespaceDeclaration) {
            clz.parent = parent
            parent.declarations.add(clz)
        } else if (parent is CsClassDeclaration) {
            clz.parent = parent
            parent.members.add(clz)
        } else if (parent is CsInterfaceDeclaration) {
            clz.parent = parent
            parent.members.add(clz)
        }
        context.registerSymbol(clz)
    }

    private fun visit(parent: CsNode, declaration: ClassOrInterfaceDeclaration) {
        val t: CsNamedTypeDeclaration
        if (declaration.isInterface) {
            val clz = CsInterfaceDeclaration()
            t = clz
            clz.parent = parent
            clz.name = declaration.nameAsString
            clz.visibility = visit(declaration.accessSpecifier)
            clz.documentation = visitDocumentation(declaration)
            clz.jSymbol = declaration.resolve()
            clz.typeParameters = declaration.typeParameters.map { visit(clz, it) }.toMutableList()
            visitAnnotations(clz, declaration.annotations)

            clz.interfaces = declaration.extendedTypes.map {
                this.createUnresolvedTypeNode(clz, it)
            }.toMutableList()

            for (m in declaration.members) {
                visit(clz, m)
            }
        } else {
            val clz = CsClassDeclaration()
            t = clz
            clz.parent = parent
            clz.name = declaration.nameAsString
            clz.visibility = visit(declaration.accessSpecifier)
            clz.documentation = visitDocumentation(declaration)
            clz.isAbstract = declaration.isAbstract
            clz.jSymbol = declaration.resolve()
            clz.typeParameters = declaration.typeParameters.map { visit(clz, it) }.toMutableList()
            visitAnnotations(clz, declaration.annotations)

            if (declaration.extendedTypes.isNonEmpty) {
                clz.baseClass = this.createUnresolvedTypeNode(clz, declaration.extendedTypes.first())
            } else if(context.overallBaseTypeName != null) {
                clz.baseClass = CsTypeReference(CsStringTypeReference(context.overallBaseTypeName!!))
            }

            clz.interfaces = declaration.implementedTypes.map {
                this.createUnresolvedTypeNode(clz, it)
            }.toMutableList()

            for (m in declaration.members) {
                visit(clz, m)
            }
        }

        if (parent is CsNamespaceDeclaration) {
            t.parent = parent
            parent.declarations.add(t)
        } else if (parent is CsClassDeclaration) {
            t.parent = parent
            parent.members.add(t)
        } else if (parent is CsInterfaceDeclaration) {
            t.parent = parent
            parent.members.add(t)
        }
        context.registerSymbol(t)
    }

    private fun visit(parent: CsNode, m: BodyDeclaration<*>) {
        when (m) {
            is InitializerDeclaration -> this.visit(parent, m as InitializerDeclaration)
            is CompactConstructorDeclaration -> this.visit(parent, m as CompactConstructorDeclaration)
            is FieldDeclaration -> this.visit(parent, m as FieldDeclaration)
            is EnumDeclaration -> this.visit(parent, m as EnumDeclaration)
            is AnnotationDeclaration -> this.visit(parent, m as AnnotationDeclaration)
            is ClassOrInterfaceDeclaration -> this.visit(parent, m as ClassOrInterfaceDeclaration)
            is RecordDeclaration -> this.visit(parent, m as RecordDeclaration)
            is ConstructorDeclaration -> this.visit(parent, m as ConstructorDeclaration)
            is MethodDeclaration -> this.visit(parent, m as MethodDeclaration)
            is AnnotationMemberDeclaration -> this.visit(parent, m as AnnotationMemberDeclaration)
        }
    }

    private fun visit(parent: CsNode, m: InitializerDeclaration) {
        // TODO collect all and put them as block into a static constructor
    }

    private fun visit(parent: CsNode, m: CompactConstructorDeclaration) {
        throw IllegalStateException("Compact constructor declaration not supported")
    }

    private fun visit(parent: CsNode, m: FieldDeclaration) {
        var isStatic = false
        var visibility = CsVisibility.Public
        var isReadonly = false

        for (mod in m.modifiers) {
            when (mod.keyword) {
                Modifier.Keyword.PUBLIC -> visibility = CsVisibility.Public
                Modifier.Keyword.PROTECTED -> visibility = CsVisibility.Protected
                Modifier.Keyword.PRIVATE -> visibility = CsVisibility.Private
                Modifier.Keyword.STATIC -> isStatic = true
                Modifier.Keyword.FINAL -> isReadonly = true
                else -> {}
            }
        }

        for (f in m.variables) {
            val csf = CsFieldDeclaration(this.createUnresolvedTypeNode(null, m.commonType))
            csf.visibility = visibility
            csf.name = context.toFieldName(f.nameAsString)
            csf.isReadonly = isReadonly
            csf.isStatic = isStatic
            csf.documentation = visitDocumentation(m)
            visitAnnotations(csf, m.annotations)
            if (f.initializer.isPresent) {
                csf.initializer = visit(csf, f.initializer.get())
            }

            if (parent is CsClassDeclaration) {
                csf.parent = parent
                parent.members.add(csf)
            }
        }
    }

    private fun visit(parent: CsNode, m: ConstructorDeclaration) {
        val csm = CsConstructorDeclaration()
        csm.parent = parent
        csm.visibility = CsVisibility.Internal
        csm.documentation = visitDocumentation(m)
        visitAnnotations(csm, m.annotations)

        for (mod in m.modifiers) {
            when (mod.keyword) {
                Modifier.Keyword.PUBLIC -> csm.visibility = CsVisibility.Public
                Modifier.Keyword.PROTECTED -> csm.visibility = CsVisibility.Protected
                Modifier.Keyword.PRIVATE -> {
                    csm.visibility = CsVisibility.Private
                }
                Modifier.Keyword.STATIC -> {
                    csm.isStatic = true
                }
                else -> {}
            }
        }

        _baseConstructorCall = null
        csm.body = visit(csm, m.body) as CsExpressionOrBlockBody
        if (_baseConstructorCall != null) {
            csm.baseConstructorArguments = _baseConstructorCall!!.arguments.map { visit(csm, it) }.toMutableList()
        }
        csm.parameters = m.parameters.map { visit(csm, it) }.toMutableList()

        if (parent is CsClassDeclaration) {
            csm.parent = parent
            parent.members.add(csm)
        }
    }

    private fun visit(parent: CsNode, m: MethodDeclaration) {
        val csm = CsMethodDeclaration(this.createUnresolvedTypeNode(null, m.type), context.toMethodName(m.nameAsString))
        csm.visibility = CsVisibility.Public
        csm.isVirtual = parent is CsClassDeclaration
        csm.documentation = visitDocumentation(m)
        visitAnnotations(csm, m.annotations)

        for (mod in m.modifiers) {
            when (mod.keyword) {
                Modifier.Keyword.PUBLIC -> csm.visibility = CsVisibility.Public
                Modifier.Keyword.PROTECTED -> csm.visibility = CsVisibility.Protected
                Modifier.Keyword.PRIVATE -> {
                    csm.visibility = CsVisibility.Private
                    csm.isVirtual = false
                }
                Modifier.Keyword.ABSTRACT -> csm.isAbstract = true
                Modifier.Keyword.STATIC -> {
                    csm.isStatic = true
                    csm.isVirtual = false
                }
                Modifier.Keyword.FINAL -> csm.isVirtual = false
                Modifier.Keyword.SYNCHRONIZED -> csm.isSynchronized = false
                else -> {}
            }
        }

        for (a in m.annotations) {
            try {
                val ar = a.resolve()
                when (ar.qualifiedName) {
                    "java.lang.Override" -> {
                        csm.isVirtual = false
                        csm.isOverride = true
                    }
                }
            } catch (_: Throwable) {
            }
        }

        if (m.body.isPresent && !m.isDefault) {
            csm.body = visit(csm, m.body.get()) as CsExpressionOrBlockBody
        }
        csm.parameters = m.parameters.map { visit(csm, it) }.toMutableList()
        csm.typeParameters = visit(csm, m.typeParameters)

        if (parent is CsClassDeclaration) {
            csm.parent = parent
            parent.members.add(csm)
        } else if (parent is CsInterfaceDeclaration) {
            if (!csm.isOverride) { // no override in interfaces
                csm.parent = parent
                parent.members.add(csm)
            }
        }
    }

    private fun visit(parent: CsNode, it: Parameter): CsParameterDeclaration {
        val p = CsParameterDeclaration()
        p.type = this.createUnresolvedTypeNode(p, it.type)
        p.name = context.toParameterName(it.nameAsString)
        p.params = it.isVarArgs
        p.parent = parent
        return p
    }


    private fun visit(parent: CsNode, m: AnnotationMemberDeclaration) {
        val csf = CsPropertyDeclaration(this.createUnresolvedTypeNode(null, m.type))
        for (mod in m.modifiers) {
            when (mod.keyword) {
                Modifier.Keyword.PUBLIC -> csf.visibility = CsVisibility.Public
                Modifier.Keyword.PROTECTED -> csf.visibility = CsVisibility.Protected
                Modifier.Keyword.PRIVATE -> csf.visibility = CsVisibility.Private
                else -> {}
            }
        }

        csf.name = context.toPropertyName(m.nameAsString)
        csf.documentation = visitDocumentation(m)
        if (m.defaultValue.isPresent) {
            csf.initializer = visit(csf, m.defaultValue.get())
        }
        csf.getAccessor = CsPropertyAccessorDeclaration("get", null)
        csf.getAccessor!!.parent = csf
        csf.setAccessor = CsPropertyAccessorDeclaration("set", null)
        csf.setAccessor!!.parent = csf

        if (parent is CsClassDeclaration) {
            csf.parent = parent
            parent.members.add(csf)
        }
    }

    private fun visit(
        clz: CsNode,
        typeParameters: NodeList<TypeParameter>
    ): MutableList<CsTypeParameterDeclaration> {
        return typeParameters.map { visit(clz, it) }.toMutableList()
    }

    private fun visit(
        parent: CsNode,
        t: TypeParameter
    ): CsTypeParameterDeclaration {
        val cst = CsTypeParameterDeclaration()
        cst.name = t.nameAsString
        cst.parent = parent
        // TODO: constraints
        return cst
    }

    private fun visitAnnotations(clz: CsAttributedElement, annotations: NodeList<AnnotationExpr>?) {
        if (annotations == null) {
            return
        }

        for (ann in annotations) {
            visit(clz, ann)
        }
    }

    private fun visit(clz: CsAttributedElement, ann: AnnotationExpr) {
        val qualifiedName = try {
            val resolved = ann.resolve()
            resolved.qualifiedName
        } catch (e: Throwable) {
            ann.nameAsString
        }
        when (qualifiedName) {
            "java.lang.SuppressWarnings" -> return
            "java.lang.Override" -> return
            "RunWith" -> return
            else -> {
                val attribute = visit(clz as CsNode, ann) as CsAttribute

                clz.attributes.add(attribute)
            }
        }
    }

    private fun visit(parent: CsNode?, expr: Expression): CsExpression {
        return when (expr) {
            is ArrayAccessExpr -> this.visit(parent, expr)
            is ClassExpr -> this.visit(parent, expr)
            is LambdaExpr -> this.visit(parent, expr)
            is ConditionalExpr -> this.visit(parent, expr)
            is MarkerAnnotationExpr -> this.visit(parent, expr)
            is SingleMemberAnnotationExpr -> this.visit(parent, expr)
            is NormalAnnotationExpr -> this.visit(parent, expr)
            is InstanceOfExpr -> this.visit(parent, expr)
            is CastExpr -> this.visit(parent, expr)
            is ThisExpr -> this.visit(parent, expr)
            is SwitchExpr -> this.visit(parent, expr)
            is NullLiteralExpr -> this.visit(parent, expr)
            is BooleanLiteralExpr -> this.visit(parent, expr)
            is TextBlockLiteralExpr -> this.visit(parent, expr)
            is CharLiteralExpr -> this.visit(parent, expr)
            is DoubleLiteralExpr -> this.visit(parent, expr)
            is LongLiteralExpr -> this.visit(parent, expr)
            is StringLiteralExpr -> this.visit(parent, expr)
            is IntegerLiteralExpr -> this.visit(parent, expr)
            is ObjectCreationExpr -> this.visit(parent, expr)
            is SuperExpr -> this.visit(parent, expr)
            is BinaryExpr -> this.visit(parent, expr)
            is PatternExpr -> this.visit(parent, expr)
            is ArrayCreationExpr -> this.visit(parent, expr)
            is MethodCallExpr -> this.visit(parent, expr)
            is AssignExpr -> this.visit(parent, expr)
            is NameExpr -> this.visit(parent, expr)
            is EnclosedExpr -> this.visit(parent, expr)
            is MethodReferenceExpr -> this.visit(parent, expr)
            is VariableDeclarationExpr -> this.visit(parent, expr)
            is UnaryExpr -> this.visit(parent, expr)
            is TypeExpr -> this.visit(parent, expr)
            is ArrayInitializerExpr -> this.visit(parent, expr)
            is FieldAccessExpr -> this.visit(parent, expr)
            else -> throw IllegalStateException("Unsupported syntax type ${expr.javaClass.name}")
        }
    }

    private fun visit(parent: CsNode?, expr: ArrayAccessExpr): CsExpression {
        return CsElementAccessExpression(
            visit(null, expr.name), visit(null, expr.index)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ClassExpr): CsExpression {
        return CsTypeOfExpression(
            this.createUnresolvedTypeNode(null, expr.type)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: LambdaExpr): CsExpression {
        return CsLambdaExpression(
            expr.parameters.map { visit(null, it, false) }.toMutableList(),
            visit(null, expr.body) as CsExpressionOrBlockBody
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ConditionalExpr): CsExpression {
        return CsConditionalExpression(
            visit(null, expr.condition), visit(null, expr.thenExpr), visit(null, expr.elseExpr)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, ann: MarkerAnnotationExpr): CsExpression {
        val attribute = CsAttribute(
            this.createUnresolvedTypeNode(
                null, ann.name, try {
                    ann.resolve()
                } catch (e: Throwable) {
                    null
                }
            )
        )
        attribute.parent = parent
        return attribute
    }

    private fun visit(parent: CsNode?, ann: SingleMemberAnnotationExpr): CsExpression {
        val attribute = CsAttribute(
            this.createUnresolvedTypeNode(
                null, ann.name, try {
                    ann.resolve()
                } catch (e: Throwable) {
                    null
                }
            )
        )
        attribute.parent = parent
        attribute.indexedArguments.add(visit(attribute, ann.memberValue))
        return attribute
    }

    private fun visit(parent: CsNode?, ann: NormalAnnotationExpr): CsExpression {
        val attribute = CsAttribute(
            this.createUnresolvedTypeNode(
                null, ann.name, try {
                    ann.resolve()
                } catch (e: Throwable) {
                    null
                }
            )
        )
        attribute.parent = parent
        for (pair in ann.pairs) {
            attribute.namedArguments.add(
                Pair(
                    context.toPropertyName(pair.nameAsString), visit(attribute, pair.value)
                )
            )
        }
        return attribute
    }

    private fun visit(parent: CsNode?, expr: InstanceOfExpr): CsExpression {
        return CsIsExpression(
            visit(null, expr.expression),
            if (expr.pattern.isPresent) this.createUnresolvedTypeNode(null, expr.pattern.get().type)
            else this.createUnresolvedTypeNode(null, expr.type)
        ).apply {
            this.parent = parent
            if (expr.pattern.isPresent) {
                this.newName = expr.pattern.get().nameAsString
            }
        }
    }

    private fun visit(parent: CsNode?, expr: CastExpr): CsExpression {
        return CsCastExpression(
            this.createUnresolvedTypeNode(null, expr.type), visit(null, expr.expression)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ThisExpr): CsExpression {
        return CsThisLiteral().apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: SwitchExpr): CsExpression {
        throw IllegalStateException("Switch expressions are not supported")
    }

    private fun visit(parent: CsNode?, expr: NullLiteralExpr): CsExpression {
        return CsNullLiteral().apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: BooleanLiteralExpr): CsExpression {
        return CsBooleanLiteral(expr.value).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: TextBlockLiteralExpr): CsExpression {
        throw IllegalStateException("TextBlocks are not supported")
    }

    private fun visit(parent: CsNode?, expr: CharLiteralExpr): CsExpression {
        return CsCharLiteral(expr.value).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: DoubleLiteralExpr): CsExpression {
        return CsDoubleLiteral(expr.value).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: LongLiteralExpr): CsExpression {
        return CsLongLiteral(expr.value).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: StringLiteralExpr): CsExpression {
        return CsStringLiteral(expr.value).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: IntegerLiteralExpr): CsExpression {
        return CsIntegerLiteral(expr.value).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ObjectCreationExpr): CsExpression {
        val type = this.createUnresolvedTypeNode(null, expr.type).apply {
            if (expr.typeArguments.isPresent) {
                this.typeArguments = expr.typeArguments.get().map {
                    createUnresolvedTypeNode(this, it)
                }.toMutableList()
            }
        }

        val newExpr = CsNewExpression(type)
        newExpr.parent = parent
        newExpr.arguments = expr.arguments.map { visit(newExpr, it) }.toMutableList()

        // implicit type parameter resolving
        if (type.jType is ResolvedReferenceType &&
            (type.jType!! as ResolvedReferenceType).typeDeclaration.isPresent
        ) {
            val typeDeclaration = (type.jType!! as ResolvedReferenceType).typeDeclaration.get()
            if (typeDeclaration.typeParameters.size != type.typeArguments.size) {
                val parentResult: Optional<Node> = expr.findAncestor(
                    { n: Node -> true },
                    VariableDeclarator::class.java as Class<Node>,
                    ObjectCreationExpr::class.java as Class<Node>,
                    MethodCallExpr::class.java as Class<Node>,
                    AssignExpr::class.java as Class<Node>,
                    ReturnStmt::class.java as Class<Node>
                )
                if (parentResult.isPresent) {
                    val parent = parentResult.get()
                    // Case 1: Simple construction Map<String, String> x = new HashMap<>()
                    // -> We're in a variable declarator and can take over the parameters from the variable
                    if (parent is VariableDeclarator) {
                        try {
                            val actualType = parent.type.resolve()
                            type.typeArguments = actualType.asReferenceType().typeParametersMap.map {
                                this.createUnresolvedTypeNode(type, null, it.b)
                            }.toMutableList()
                        } catch (e: Throwable) {
                            // TODO: workaround until https://github.com/javaparser/javaparser/issues/3550 is solved
                            if (parent.type.isClassOrInterfaceType &&
                                parent.type.asClassOrInterfaceType().typeArguments.isPresent
                            ) {
                                type.typeArguments = parent.type.asClassOrInterfaceType().typeArguments.get().map {
                                    CsTypeReference(CsStringTypeReference(it.asString())).apply {
                                        this.parent = type
                                    }
                                }.toMutableList()
                            }
                        }
                    }
                    // Case 2: We are a parameter in a constructor new Other(new HashMap<>())
                    // -> We resolve the type from the constructor definition
                    else if (parent is ObjectCreationExpr) {
                        val argIndex = parent.arguments.indexOf(expr)
                        if (argIndex == -1) {
                            throw IllegalStateException("Could not determine arg index")
                        }
                        val actualType = parent.resolve().getParam(argIndex).type
                        type.typeArguments = actualType.asReferenceType().typeParametersMap.map {
                            this.createUnresolvedTypeNode(type, null, it.b)
                        }.toMutableList()
                    }
                    // Case 3: We are a parameter in a method TestMethod(new HashMap<>())
                    // -> We resolve the type from the method definition
                    else if (parent is MethodCallExpr) {
                        val argIndex = parent.arguments.indexOf(expr)
                        if (argIndex == -1) {
                            throw IllegalStateException("Could not determine arg index")
                        }
                        val actualType = parent.resolve().getParam(argIndex).type
                        type.typeArguments = actualType.asReferenceType().typeParametersMap.map {
                            this.createUnresolvedTypeNode(type, null, it.b)
                        }.toMutableList()
                    }
                    // Case 4: We assign any variable or member x.y = new HashMap<>()
                    // -> We resolve the type from the member definition
                    else if (parent is AssignExpr) {
                        val resolved = parent.calculateResolvedType()
                        type.typeArguments = resolved.asReferenceType().typeParametersMap.map {
                            this.createUnresolvedTypeNode(type, null, it.b)
                        }.toMutableList()
                    }
                    // Case 5: We return a value like return new HashMap<>()
                    // -> We resolve the type from the method return type
                    else if (parent is ReturnStmt) {
                        val decl = parent.findAncestor(MethodDeclaration::class.java)
                        if (!decl.isPresent) {
                            throw IllegalStateException("Could not find method declaration of return")
                        }

                        val resolved = decl.get().type.resolve()
                        type.typeArguments = resolved.asReferenceType().typeParametersMap.map {
                            this.createUnresolvedTypeNode(type, null, it.b)
                        }.toMutableList()
                    }
                }
                // Not supported
                else {
                    throw IllegalStateException("Could not resolve implicit generic types")
                }
            }
        }

        // TODO: anonymous class body

        return newExpr
    }

    private fun visit(parent: CsNode?, expr: SuperExpr): CsExpression {
        return CsBaseLiteral().apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: BinaryExpr): CsExpression {
        return if (expr.operator == BinaryExpr.Operator.UNSIGNED_RIGHT_SHIFT) {
            val invocation = CsInvocationExpression(
                CsIdentifier("SigningServer.Android.TypeUtils.UnsignedRightShift")
            ).apply {
                this.parent = parent
            }
            invocation.arguments.add(visit(null, expr.left).apply {
                this.parent = invocation
            })
            invocation.arguments.add(visit(null, expr.right).apply {
                this.parent = invocation
            })
            invocation
        } else {
            CsBinaryExpression(
                visit(null, expr.left), visit(expr.operator!!), visit(null, expr.right)
            ).apply {
                this.parent = parent
            }
        }

    }

    private fun visit(op: BinaryExpr.Operator): String {
        return when (op) {
            BinaryExpr.Operator.OR -> "||"
            BinaryExpr.Operator.AND -> "&&"
            BinaryExpr.Operator.BINARY_OR -> "|"
            BinaryExpr.Operator.BINARY_AND -> "&"
            BinaryExpr.Operator.XOR -> "^"
            BinaryExpr.Operator.EQUALS -> "=="
            BinaryExpr.Operator.NOT_EQUALS -> "!="
            BinaryExpr.Operator.LESS -> "<"
            BinaryExpr.Operator.GREATER -> ">"
            BinaryExpr.Operator.LESS_EQUALS -> "<="
            BinaryExpr.Operator.GREATER_EQUALS -> ">="
            BinaryExpr.Operator.LEFT_SHIFT -> "<<"
            BinaryExpr.Operator.SIGNED_RIGHT_SHIFT -> ">>"
            BinaryExpr.Operator.UNSIGNED_RIGHT_SHIFT -> ">>"
            BinaryExpr.Operator.PLUS -> "+"
            BinaryExpr.Operator.MINUS -> "-"
            BinaryExpr.Operator.MULTIPLY -> "*"
            BinaryExpr.Operator.DIVIDE -> "/"
            BinaryExpr.Operator.REMAINDER -> "%"
        }
    }

    private fun visit(parent: CsNode?, expr: ArrayCreationExpr): CsExpression {
        val arr = CsArrayCreationExpression()
        arr.parent = parent
        arr.type = CsArrayTypeNode(this.createUnresolvedTypeNode(arr, expr.elementType))
        arr.sizeExpressions = expr.levels.map {
            if (it.dimension.isPresent) {
                visit(arr, it.dimension.get())
            } else {
                null
            }
        }.toMutableList()

        if (expr.initializer.isPresent) {
            arr.values =
                expr.initializer.get().values.map { visit(arr, it).apply { this.parent = arr } }.toMutableList()
        }

        return arr
    }

    private fun visit(parent: CsNode?, expr: MethodCallExpr): CsExpression {
        var qualifiedMethodName = ""
        var methodName = context.toMethodName(expr.nameAsString)
        var resolved: ResolvedMethodDeclaration? = null
        try {
            resolved = expr.resolve()
            qualifiedMethodName = resolved.qualifiedName
            when (qualifiedMethodName) {
                "java.io.InputStream.close" -> methodName = "Dispose"
                "java.io.OutputStream.close" -> methodName = "Dispose"
                "java.io.Closeable.close" -> methodName = "Dispose"
                "java.io.Closeable.close" -> methodName = "Dispose"
                else -> {}
            }
        } catch (_: Throwable) {
        }


        val invocation = CsInvocationExpression(
            if (resolved != null && resolved.isStatic) {
                CsMemberAccessExpression(
                    this.createUnresolvedTypeNode(null, null, resolved.declaringType()),
                    methodName
                )
            } else if (expr.scope.isPresent) {
                CsMemberAccessExpression(
                    visit(null, expr.scope.get()), methodName
                )
            } else {
                CsIdentifier(methodName)
            }
        )
        invocation.parent = parent

        if (expr.typeArguments.isPresent) {
            invocation.typeArguments = expr.typeArguments.get().map {
                this.createUnresolvedTypeNode(invocation, it)
            }.toMutableList()
        } else if (resolved != null && resolved.typeParameters.isNotEmpty()) {
            val typeParameterLookup = HashMap<String, ResolvedType?>()
            for (tp in resolved.typeParameters) {
                typeParameterLookup[tp.qualifiedName] = null
            }

            for ((index, a) in expr.arguments.withIndex()) {
                val argDef = if (index < resolved.numberOfParams)
                    resolved.getParam(index)
                else if (resolved.getParam(resolved.numberOfParams - 1).isVariadic)
                    resolved.getParam(resolved.numberOfParams - 1)
                else
                    null

                if (argDef != null && argDef.type.isTypeVariable) {
                    if (typeParameterLookup.containsKey(argDef.type.asTypeVariable().qualifiedName())) {
                        try {
                            typeParameterLookup[argDef.type.asTypeVariable().qualifiedName()] =
                                a.calculateResolvedType()
                        } catch (_: Throwable) {
                            // ignore
                        }
                    }
                }
            }

            if (!typeParameterLookup.any { it.value == null }) {
                invocation.typeArguments = resolved.typeParameters.map {
                    this.createUnresolvedTypeNode(invocation, null, typeParameterLookup.get(it.qualifiedName)!!)
                }.toMutableList()
            }
        }

        when (qualifiedMethodName) {
            "java.util.List.toArray" -> {}
            else ->
                for (a in expr.arguments) {
                    invocation.arguments.add(visit(invocation, a))
                }
        }

        return invocation
    }

    private fun visit(parent: CsNode?, expr: AssignExpr): CsExpression {
        if (expr.operator == AssignExpr.Operator.UNSIGNED_RIGHT_SHIFT) {
            val invocation = CsInvocationExpression(
                CsIdentifier("SigningServer.Android.TypeUtils.UnsignedRightShift")
            ).apply {
                this.parent = parent
            }
            invocation.arguments.add(visit(null, expr.target).apply {
                this.parent = invocation
            })
            invocation.arguments.add(visit(null, expr.value).apply {
                this.parent = invocation
            })

            return CsBinaryExpression(
                visit(null, expr.target),
                visit(expr.operator),
                invocation
            ).apply {
                this.parent = parent
            }
        } else {
            return CsBinaryExpression(
                visit(null, expr.target),
                visit(expr.operator),
                visit(null, expr.value)
            ).apply {
                this.parent = parent
            }
        }

    }

    private fun visit(operator: AssignExpr.Operator): String {
        return when (operator) {
            AssignExpr.Operator.ASSIGN -> "="
            AssignExpr.Operator.PLUS -> "+="
            AssignExpr.Operator.MINUS -> "-="
            AssignExpr.Operator.MULTIPLY -> "*="
            AssignExpr.Operator.DIVIDE -> "/="
            AssignExpr.Operator.BINARY_AND -> "&="
            AssignExpr.Operator.BINARY_OR -> "|="
            AssignExpr.Operator.XOR -> "^="
            AssignExpr.Operator.REMAINDER -> "%="
            AssignExpr.Operator.LEFT_SHIFT -> "<<"
            AssignExpr.Operator.SIGNED_RIGHT_SHIFT -> ">>"
            AssignExpr.Operator.UNSIGNED_RIGHT_SHIFT -> ">>"
        }
    }

    private fun visit(parent: CsNode?, expr: NameExpr): CsExpression {
        var name = expr.nameAsString
        try {
            val resolved = expr.resolve()
            if (resolved.isType) {
                return this.createUnresolvedTypeNode(parent, expr.name, resolved)
            } else if (resolved.isParameter) {
                name = context.toParameterName(name)
            } else if (resolved.isVariable) {
                name = context.toLocalVariable(name)
            } else if (resolved.isField) {
                name = context.toLocalVariable(name)
                if (resolved.asField().isStatic) {
                    return CsMemberAccessExpression(
                        this.createUnresolvedTypeNode(null, null, resolved.asField().declaringType()),
                        name
                    ).apply {
                        this.parent = parent
                    }
                }
            } else if (resolved.isMethod) {
                name = context.toMethodName(name)
                return CsMemberAccessExpression(
                    this.createUnresolvedTypeNode(null, null, resolved.asMethod().declaringType()),
                    name
                ).apply {
                    this.parent = parent
                }
            } else if (resolved.isEnumConstant) {
                val enum = CsMemberAccessExpression(
                    this.createUnresolvedTypeNode(null, null, resolved.asEnumConstant().type),
                    name
                ).apply {
                    this.parent = parent
                }

                if (!_enumSwitchStack.empty() && _enumSwitchStack.peek()) {
                    enum.member += "_CASE"
                }
                return enum
            }
        } catch (e: Throwable) {
            // ignore
        }

        return CsIdentifier(name).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: EnclosedExpr): CsExpression {
        return CsParenthesizedExpression(visit(null, expr.inner)).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: MethodReferenceExpr): CsExpression {
        if (expr.typeArguments.isPresent) {
            throw IllegalStateException("Method Reference expressions with type parameters not supported")
        }
        return CsMemberAccessExpression(
            visit(null, expr.scope),
            expr.identifier
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: VariableDeclarationExpr): CsExpression {
        val decl = CsVariableDeclarationList()
        decl.parent = parent

        decl.declarations = expr.variables.map { visit(decl, it) }.toMutableList()

        return decl
    }


    private fun visit(parent: CsNode?, expr: VariableDeclarator): CsVariableDeclaration {
        val decl = CsVariableDeclaration(
            this.createUnresolvedTypeNode(null, expr.type),
            context.toLocalVariable(expr.nameAsString),
            null,
            if (expr.initializer.isPresent) visit(null, expr.initializer.get()) else null
        )
        decl.parent = parent
        return decl
    }


    private fun visit(parent: CsNode?, expr: UnaryExpr): CsExpression {
        if (expr.isPrefix) {
            return CsPrefixUnaryExpression(
                visit(null, expr.expression),
                visit(expr.operator)
            ).apply {
                this.parent = parent
            }
        } else {
            return CsPostfixUnaryExpression(
                visit(null, expr.expression),
                visit(expr.operator)
            ).apply {
                this.parent = parent
            }
        }
    }

    private fun visit(operator: UnaryExpr.Operator): String {
        return when (operator) {
            UnaryExpr.Operator.PLUS -> "+"
            UnaryExpr.Operator.MINUS -> "-"
            UnaryExpr.Operator.PREFIX_INCREMENT -> "++"
            UnaryExpr.Operator.PREFIX_DECREMENT -> "--"
            UnaryExpr.Operator.LOGICAL_COMPLEMENT -> "!"
            UnaryExpr.Operator.BITWISE_COMPLEMENT -> "~"
            UnaryExpr.Operator.POSTFIX_INCREMENT -> "++"
            UnaryExpr.Operator.POSTFIX_DECREMENT -> "--"
        }
    }

    private fun visit(parent: CsNode?, expr: TypeExpr): CsExpression {
        return this.createUnresolvedTypeNode(parent, expr.type)
    }

    private fun visit(parent: CsNode?, expr: ArrayInitializerExpr): CsExpression {
        return CsArrayInitializerExpression().apply {
            val init = this
            this.parent = parent
            this.values = expr.values.map { visit(null, it).apply { this.parent = init } }.toMutableList()
        }
    }

    private fun visit(parent: CsNode?, expr: FieldAccessExpr): CsExpression {
        var fieldName = context.toFieldName(expr.nameAsString)
        try {
            val resolved = expr.resolve()
            if (resolved.isField) {
                val field = (resolved as ResolvedFieldDeclaration)
                val fieldQualifier = field.declaringType().qualifiedName + "." + field.name

                if (field.isStatic) {
                    if (expr.parentNode.get() is SwitchEntry &&
                        (expr.parentNode.get() as SwitchEntry).labels.contains(expr)
                    ) {
                        this.context.registerSymbolAsConst(field);
                    }

                    when (fieldQualifier) {
                        "java.lang.Integer.MAX_VALUE" -> fieldName = "MaxValue"
                        else -> {}
                    }

                    return CsMemberAccessExpression(
                        CsTypeReference(this.createUnresolvedTypeNode(null, null, field.declaringType())),
                        fieldName
                    ).apply {
                        this.parent = parent
                    }
                } else {
                    when (fieldQualifier) {
                        "java.lang.String.length" -> fieldName = "Length"
                        else -> {}
                    }
                }


            } else if (resolved.isEnumConstant) {
                val field = (resolved as ResolvedEnumConstantDeclaration)

                return CsMemberAccessExpression(
                    CsTypeReference(this.createUnresolvedTypeNode(null, null, field.type)),
                    fieldName
                ).apply {
                    this.parent = parent
                }
            } else if (expr.name.id == "length" && expr.scope.calculateResolvedType().isArray) {
                fieldName = "Length"
            }
        } catch (e: Throwable) {
            // ignore
        }

        return CsMemberAccessExpression(
            visit(null, expr.scope),
            fieldName
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: Parameter, isCatchClause: Boolean): CsParameterDeclaration {
        val p = CsParameterDeclaration()
        p.parent = parent
        p.type = if (expr.type.isUnknownType)
            null
        else if (expr.type.isUnionType && isCatchClause)
            CsTypeReference(
                CsStringTypeReference("System.Exception")
            ).apply {
                this.parent = p
            }
        else this.createUnresolvedTypeNode(p, expr.type)
        p.name = context.toParameterName(expr.nameAsString)
        p.params = expr.isVarArgs
        // TODO: javadoc
        return p
    }

    private fun visit(parent: CsNode?, expr: Statement): CsStatement {
        return when (expr) {
            is ForEachStmt -> this.visit(parent, expr)
            is LocalClassDeclarationStmt -> this.visit(parent, expr)
            is ContinueStmt -> this.visit(parent, expr)
            is ExpressionStmt -> this.visit(parent, expr)
            is LabeledStmt -> this.visit(parent, expr)
            is YieldStmt -> this.visit(parent, expr)
            is ReturnStmt -> this.visit(parent, expr)
            is WhileStmt -> this.visit(parent, expr)
            is EmptyStmt -> this.visit(parent, expr)
            is UnparsableStmt -> this.visit(parent, expr)
            is IfStmt -> this.visit(parent, expr)
            is BreakStmt -> this.visit(parent, expr)
            is AssertStmt -> this.visit(parent, expr)
            is ExplicitConstructorInvocationStmt -> this.visit(parent, expr)
            is DoStmt -> this.visit(parent, expr)
            is ForStmt -> this.visit(parent, expr)
            is ThrowStmt -> this.visit(parent, expr)
            is TryStmt -> this.visit(parent, expr)
            is SwitchStmt -> this.visit(parent, expr)
            is SynchronizedStmt -> this.visit(parent, expr)
            is LocalRecordDeclarationStmt -> this.visit(parent, expr)
            is BlockStmt -> this.visit(parent, expr)
            else -> throw IllegalStateException("Unsupported syntax type ${expr.javaClass.name}")
        }
    }

    private fun visit(parent: CsNode?, expr: ForEachStmt): CsStatement {
        return CsForEachStatement(
            visit(null, expr.variable),
            visit(null, expr.iterable),
            visit(null, expr.body)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: LocalClassDeclarationStmt): CsStatement {
        throw IllegalStateException("Local class declaration statements are not supported")
    }

    private fun visit(parent: CsNode?, expr: ContinueStmt): CsStatement {
        return CsContinueStatement().apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ExpressionStmt): CsStatement {
        return CsExpressionStatement(visit(null, expr.expression)).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: LabeledStmt): CsStatement {
        throw IllegalStateException("Labelled statements are not supported")
    }

    private fun visit(parent: CsNode?, expr: YieldStmt): CsStatement {
        throw IllegalStateException("Yield statements are not supported")
    }

    private fun visit(parent: CsNode?, expr: ReturnStmt): CsStatement {
        val ret = CsReturnStatement()
        ret.parent = parent
        if (expr.expression.isPresent) {
            ret.expression = visit(ret, expr.expression.get())
        }
        return ret
    }

    private fun visit(parent: CsNode?, expr: WhileStmt): CsStatement {
        return CsWhileStatement(
            visit(null, expr.condition),
            visit(null, expr.body)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: EmptyStmt): CsStatement {
        return CsEmptyStatement().apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: UnparsableStmt): CsStatement {
        throw IllegalStateException("Encountered unparsable statement")
    }

    private fun visit(parent: CsNode?, expr: IfStmt): CsStatement {
        return CsIfStatement(
            visit(null, expr.condition),
            visit(null, expr.thenStmt),
            if (expr.elseStmt.isPresent) visit(null, expr.elseStmt.get()) else null
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: BreakStmt): CsStatement {
        return CsBreakStatement().apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: AssertStmt): CsStatement {
        throw IllegalStateException("Assert Statement are not supported")
    }

    private var _baseConstructorCall: ExplicitConstructorInvocationStmt? = null
    private fun visit(parent: CsNode?, expr: ExplicitConstructorInvocationStmt): CsStatement {
        _baseConstructorCall = expr // handled as part of constructor declaration
        return CsEmptyStatement().apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: DoStmt): CsStatement {
        return CsDoStatement(
            visit(null, expr.condition),
            visit(null, expr.body)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ForStmt): CsStatement {
        return CsForStatement(
            expr.initialization.map { visit(null, it) }.toMutableList(),
            if (expr.compare.isPresent) visit(null, expr.compare.get()) else null,
            expr.update.map { visit(null, it) }.toMutableList(),
            visit(null, expr.body)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ThrowStmt): CsStatement {
        return CsThrowStatement(
            visit(null, expr.expression)
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: TryStmt): CsStatement {
        val tryBlock = visit(null, expr.tryBlock) as CsBlock

        if (expr.resources.isNotEmpty()) {
            val usingBlock = CsUsingStatement(expr.resources.map { visit(null, it) }.toMutableList(), CsBlock())
            usingBlock.parent = tryBlock
            for (s in tryBlock.statements) {
                s.parent = usingBlock
                usingBlock.body.statements.add(s)
            }

            if (expr.catchClauses.isEmpty() && expr.finallyBlock.isEmpty) {
                usingBlock.parent = parent
                return usingBlock
            }

            tryBlock.statements.clear()
            tryBlock.statements.add(usingBlock)
        }

        val t = CsTryStatement(tryBlock)
        t.catchClauses = expr.catchClauses.map {
            CsCatchClause(
                visit(null, it.parameter, true),
                visit(null, it.body) as CsBlock
            ).apply {
                this.parent = t
                if (it.parameter.type.isUnionType) {
                    val unionType = it.parameter.type as UnionType
                    for (t in unionType.elements) {
                        this.whenTypeClauses.add(this@CSharpAstTransformer.createUnresolvedTypeNode(this, t))
                    }
                }
            }
        }.toMutableList()

        if (expr.finallyBlock.isPresent) {
            t.finallyBlock = visit(t, expr.finallyBlock.get()) as CsBlock
        }

        t.parent = parent
        return t
    }

    private val _enumSwitchStack = Stack<Boolean>()
    private fun visit(parent: CsNode?, expr: SwitchStmt): CsStatement {
        val isEnumSwitch = try {
            val resolved = expr.selector.calculateResolvedType()
            resolved.isReferenceType && resolved.asReferenceType().typeDeclaration.isPresent &&
                    resolved.asReferenceType().typeDeclaration.get().isEnum &&
                    resolved.asReferenceType().typeDeclaration.get().asEnum().declaredMethods.isNotEmpty()
        } catch (e: Exception) {
            false
        }

        var selector = visit(null, expr.selector)
        if (isEnumSwitch) {
            selector = CsMemberAccessExpression(selector, "Case")
        }
        val s = CsSwitchStatement(selector)
        s.caseClauses = expr.entries.map {
            if (it.labels.isEmpty()) {
                CsDefaultClause().apply {
                    val c = this
                    this.parent = s
                    this.statements = it.statements.map { visit(c, it) }.toMutableList()
                }
            } else if (it.labels.size > 1) {
                throw IllegalStateException("Cases with multiple labels not supported")
            } else {
                _enumSwitchStack.push(isEnumSwitch)
                val label = visit(null, it.labels.first())
                _enumSwitchStack.pop()
                CsCaseClause(label).apply {
                    val c = this
                    this.parent = s
                    this.statements = it.statements.map { visit(c, it) }.toMutableList()
                }
            }
        }.toMutableList()
        s.parent = parent
        return s
    }

    private fun visit(parent: CsNode?, expr: SynchronizedStmt): CsStatement {
        return CsLockStatement(
            visit(null, expr.expression),
            visit(null, expr.body) as CsBlock
        ).apply {
            this.parent = this
        }
    }

    private fun visit(parent: CsNode?, expr: LocalRecordDeclarationStmt): CsStatement {
        throw IllegalStateException("Records are not supported")
    }

    private fun visit(parent: CsNode?, expr: BlockStmt): CsStatement {
        val b = CsBlock()
        b.parent = parent
        b.statements = expr.statements.map { visit(b, it) }.toMutableList()
        return b
    }

    private fun createUnresolvedTypeNode(
        parent: CsNode?, name: Type
    ): CsUnresolvedTypeNode {
        val node = CsUnresolvedTypeNode()
        node.parent = parent
        if (name.isArrayType) {
            try {
                node.jType = name.resolve()
                if (node.jType!!.isReferenceType) {
                    node.typeArguments = node.jType!!.asReferenceType().typeParametersMap.map {
                        this.createUnresolvedTypeNode(node, null, it.b)
                    }.toMutableList()
                }
            } catch (e: Throwable) {
                node.resolved = CsArrayTypeNode(
                    this.createUnresolvedTypeNode(null, name.elementType)
                )
                node.resolved!!.parent = parent
            }
        } else {
            try {
                node.jType = name.resolve()
                if (node.jType!!.isReferenceType) {
                    node.typeArguments = node.jType!!.asReferenceType().typeParametersMap.map {
                        this.createUnresolvedTypeNode(node, null, it.b)
                    }.toMutableList()
                }
            } catch (e: Throwable) {
                if (name.isTypeParameter) {
                    node.resolved = CsTypeReference(CsStringTypeReference(name.asTypeParameter().nameAsString))
                    node.resolved!!.parent = parent
                } else {
                    node.resolved =
                        CsPrimitiveTypeNode(CsPrimitiveType.Var) // fallback to var, most of the time it should work
                    node.resolved!!.parent = parent
                }
            }
        }

        node.jNode = name
        this.context.registerUnresolvedTypeNode(node);
        return node
    }

    private fun createUnresolvedTypeNode(
        parent: CsNode?, name: Node?, resolved: ResolvedType
    ): CsTypeNode {
        val node = CsUnresolvedTypeNode()
        node.parent = parent
        node.jType = resolved
        node.jNode = name
        this.context.registerUnresolvedTypeNode(node);
        return node
    }

    private fun createUnresolvedTypeNode(
        parent: CsNode?, name: Node?, resolved: ResolvedDeclaration?
    ): CsTypeNode {
        val node = CsUnresolvedTypeNode()
        node.parent = parent
        node.jDeclaration = resolved
        node.jNode = name
        this.context.registerUnresolvedTypeNode(node);
        return node
    }

    private fun visit(parent: CsNode, declaration: RecordDeclaration) {
        context.addJNodeDiagnostics(declaration, "Records are not supported yet", true)
    }

    private fun visit(
        csharpFile: CsSourceFile, packageDeclaration: Optional<PackageDeclaration>?
    ): CsNamespaceDeclaration? {
        if (packageDeclaration == null || packageDeclaration.isEmpty) {
            return CsNamespaceDeclaration().apply {
                this.parent = csharpFile
                this.namespace = "SigningServer.Android"
            }
        } else {
            return CsNamespaceDeclaration().apply {
                this.parent = csharpFile
                this.namespace = "SigningServer.Android"
                val flattenedName = context.getFullName(packageDeclaration.get().name)
                if (!flattenedName.isNullOrBlank()) {
                    this.namespace += ".${flattenedName}"
                }
            }
        }
    }
}