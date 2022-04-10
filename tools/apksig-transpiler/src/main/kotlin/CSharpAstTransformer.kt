import com.github.javaparser.ast.*
import com.github.javaparser.ast.body.*
import com.github.javaparser.ast.comments.JavadocComment
import com.github.javaparser.ast.expr.*
import com.github.javaparser.ast.stmt.AssertStmt
import com.github.javaparser.ast.stmt.BlockStmt
import com.github.javaparser.ast.stmt.BreakStmt
import com.github.javaparser.ast.stmt.ContinueStmt
import com.github.javaparser.ast.stmt.DoStmt
import com.github.javaparser.ast.stmt.EmptyStmt
import com.github.javaparser.ast.stmt.ExplicitConstructorInvocationStmt
import com.github.javaparser.ast.stmt.ExpressionStmt
import com.github.javaparser.ast.stmt.ForEachStmt
import com.github.javaparser.ast.stmt.ForStmt
import com.github.javaparser.ast.stmt.IfStmt
import com.github.javaparser.ast.stmt.LabeledStmt
import com.github.javaparser.ast.stmt.LocalClassDeclarationStmt
import com.github.javaparser.ast.stmt.LocalRecordDeclarationStmt
import com.github.javaparser.ast.stmt.ReturnStmt
import com.github.javaparser.ast.stmt.Statement
import com.github.javaparser.ast.stmt.SwitchStmt
import com.github.javaparser.ast.stmt.SynchronizedStmt
import com.github.javaparser.ast.stmt.ThrowStmt
import com.github.javaparser.ast.stmt.TryStmt
import com.github.javaparser.ast.stmt.UnparsableStmt
import com.github.javaparser.ast.stmt.WhileStmt
import com.github.javaparser.ast.stmt.YieldStmt
import com.github.javaparser.ast.type.Type
import com.github.javaparser.ast.type.TypeParameter
import com.github.javaparser.resolution.declarations.ResolvedAnnotationDeclaration
import com.github.javaparser.resolution.declarations.ResolvedDeclaration
import com.github.javaparser.resolution.declarations.ResolvedEnumConstantDeclaration
import com.github.javaparser.resolution.declarations.ResolvedFieldDeclaration
import com.github.javaparser.resolution.types.ResolvedType
import java.nio.file.Path
import java.nio.file.Paths
import java.util.*
import kotlin.collections.ArrayList
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
        val t:CsNamedTypeDeclaration
        if (declaration.members.isNotEmpty()) {
            val clz = CsInterfaceDeclaration()
            t = clz
            clz.parent = parent
            clz.name = declaration.nameAsString
            clz.visibility = visit(declaration.accessSpecifier)
            clz.documentation = visitDocumentation(declaration)
            clz.jSymbol = declaration.resolve()
            visitAnnotations(clz, declaration.annotations)
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
            parent.declarations.add(t)
        } else if (parent is CsClassDeclaration) {
            parent.members.add(t)
        } else if (parent is CsInterfaceDeclaration) {
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


        if (parent is CsNamespaceDeclaration) {
            parent.declarations.add(clz)
        } else if (parent is CsClassDeclaration) {
            parent.members.add(clz)
        } else if (parent is CsInterfaceDeclaration) {
            parent.members.add(clz)
        }
        context.registerSymbol(clz)
    }

    private fun visit(parent: CsNode, declaration: ClassOrInterfaceDeclaration) {
        val t:CsNamedTypeDeclaration
        if (declaration.isInterface) {
            val clz = CsInterfaceDeclaration()
            t = clz
            clz.parent = parent
            clz.name = declaration.nameAsString
            clz.visibility = visit(declaration.accessSpecifier)
            clz.documentation = visitDocumentation(declaration)
            clz.jSymbol = declaration.resolve()
            visitAnnotations(clz, declaration.annotations)

            clz.typeParameters = visit(clz, declaration.typeParameters)

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
            visitAnnotations(clz, declaration.annotations)

            if (declaration.extendedTypes.isNonEmpty) {
                clz.baseClass = this.createUnresolvedTypeNode(clz, declaration.extendedTypes.first())
            }

            clz.interfaces = declaration.implementedTypes.map {
                this.createUnresolvedTypeNode(clz, it)
            }.toMutableList()

            for (m in declaration.members) {
                visit(clz, m)
            }
        }

        if (parent is CsNamespaceDeclaration) {
            parent.declarations.add(t)
        } else if (parent is CsClassDeclaration) {
            parent.members.add(t)
        } else if (parent is CsInterfaceDeclaration) {
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
        // TODO
    }

    private fun visit(parent: CsNode, m: CompactConstructorDeclaration) {
        throw IllegalStateException("Compact constructor declaration not supported")
    }

    private fun visit(parent: CsNode, m: FieldDeclaration) {
    }

    private fun visit(parent: CsNode, m: ConstructorDeclaration) {
    }

    private fun visit(parent: CsNode, m: MethodDeclaration) {
    }

    private fun visit(parent: CsNode, m: AnnotationMemberDeclaration) {
    }

    private fun visit(
        clz: CsInterfaceDeclaration,
        typeParameters: NodeList<TypeParameter>
    ): MutableList<CsTypeParameterDeclaration> {
        val cstp = ArrayList<CsTypeParameterDeclaration>()
        for (t in typeParameters) {
            val cst = CsTypeParameterDeclaration()
            cst.name = t.nameAsString
            cst.parent = clz
            // TODO: constraints
            cstp.add(cst)
        }
        return cstp
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
        val resolved = ann.resolve()
        if(resolved.qualifiedName == "java.lang.SuppressWarnings") {
            return
        }
        val attribute = visit(clz as CsNode, ann) as CsAttribute

        clz.attributes.add(attribute)
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
            is LiteralStringValueExpr -> this.visit(parent, expr)
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
            expr.parameters.map { visit(null, it) }.toMutableList(), visit(null, expr.body) as CsExpressionOrBlockBody
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
        val attribute = CsAttribute(this.createUnresolvedTypeNode(null, ann.name, ann.resolve()))
        attribute.parent = parent
        return attribute
    }

    private fun visit(parent: CsNode?, ann: SingleMemberAnnotationExpr): CsExpression {
        val attribute = CsAttribute(this.createUnresolvedTypeNode(null, ann.name, ann.resolve()))
        attribute.parent = parent
        attribute.indexedArguments.add(visit(attribute, ann.memberValue))
        return attribute
    }

    private fun visit(parent: CsNode?, ann: NormalAnnotationExpr): CsExpression {
        val attribute = CsAttribute(this.createUnresolvedTypeNode(null, ann.name, ann.resolve()))
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

    private fun visit(parent: CsNode?, expr: LiteralStringValueExpr): CsExpression {
        return CsStringLiteral(expr.value).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: ObjectCreationExpr): CsExpression {
        throw IllegalStateException("Object creations expressions are not supported")
        // TODO: generate a nested class and instanciate it here
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
        arr.type = this.createUnresolvedTypeNode(arr, expr.elementType)
        if (expr.levels.size == 1) {
            if (expr.levels[0].dimension.isPresent) {
                arr.sizeExpression = visit(arr, expr.levels[0].dimension.get())
            }
        } else {
            throw IllegalStateException("Multidimensional arrays not supported")
        }

        if (expr.initializer.isPresent) {
            arr.values =
                expr.initializer.get().values.map { visit(arr, it).apply { this.parent = arr } }.toMutableList()
        }

        return arr
    }

    private fun visit(parent: CsNode?, expr: MethodCallExpr): CsExpression {
        val invocation = CsInvocationExpression(
            if (expr.scope.isPresent) CsMemberAccessExpression(
                visit(null, expr.scope.get()), context.toMethodName(expr.nameAsString)
            )
            else CsIdentifier(expr.nameAsString)
        )
        invocation.parent = parent

        if (expr.typeArguments.isPresent) {
            invocation.typeArguments = expr.typeArguments.get().map {
                this.createUnresolvedTypeNode(invocation, it)
            }.toMutableList()
        }

        for (a in expr.arguments) {
            invocation.arguments.add(visit(invocation, a))
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
        try {
            val resolved = expr.resolve()
            if (resolved.isType) {
                return this.createUnresolvedTypeNode(parent, expr.name, resolved)
            }
        } catch (e: Throwable) {
            // ignore
        }

        return CsIdentifier(expr.nameAsString).apply {
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
            expr.nameAsString,
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
        try {
            val resolved = expr.resolve()
            if (resolved.isField) {
                val field = (resolved as ResolvedFieldDeclaration)
                if (field.isStatic) {
                    return CsMemberAccessExpression(
                        CsTypeReference(this.createUnresolvedTypeNode(null, null, field.type)),
                        context.toFieldName(field.name)
                    ).apply {
                        this.parent = parent
                    }
                }
            } else if (resolved.isEnumConstant) {
                val field = (resolved as ResolvedEnumConstantDeclaration)

                return CsMemberAccessExpression(
                    CsTypeReference(this.createUnresolvedTypeNode(null, null, field.type)),
                    context.toFieldName(field.name)
                ).apply {
                    this.parent = parent
                }
            }
        } catch (e: Throwable) {
            // ignore
        }

        return CsMemberAccessExpression(
            visit(null, expr.scope),
            expr.nameAsString
        ).apply {
            this.parent = parent
        }
    }

    private fun visit(parent: CsNode?, expr: Parameter): CsParameterDeclaration {
        val p = CsParameterDeclaration()
        p.parent = parent
        p.type = this.createUnresolvedTypeNode(p, expr.type)
        p.name = expr.nameAsString
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
        val t = CsTryStatement(visit(null, expr.tryBlock) as CsBlock)
        t.catchClauses = expr.catchClauses.map {
            CsCatchClause(
                visit(null, it.parameter),
                visit(null, it.body) as CsBlock
            ).apply {
                this.parent = t
            }
        }.toMutableList()
        t.parent = parent
        return t
    }

    private fun visit(parent: CsNode?, expr: SwitchStmt): CsStatement {
        val s = CsSwitchStatement(visit(null, expr.selector))
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
                CsCaseClause(visit(null, it.labels.first())).apply {
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
    ): CsTypeNode {
        val node = CsUnresolvedTypeNode()
        node.parent = parent
        node.jType = name.resolve()
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
        parent: CsNode?, name: Node?, resolved: ResolvedDeclaration
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