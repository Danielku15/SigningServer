import com.github.javaparser.resolution.declarations.ResolvedDeclaration
import com.github.javaparser.resolution.types.ResolvedType
import java.nio.file.Path
import java.nio.file.Paths

enum class CsSyntaxKind {
    SourceFile,
    UsingDeclaration,
    NamespaceDeclaration,
    ClassDeclaration,
    EnumDeclaration,
    InterfaceDeclaration,
    TypeParameterDeclaration,
    MethodDeclaration,
    ConstructorDeclaration,
    FieldDeclaration,
    PropertyDeclaration,
    PropertyAccessorDeclaration,
    ParameterDeclaration,
    UnresolvedTypeNode,
    TypeReference,
    PrimitiveTypeNode,
    EnumMember,
    ArrayTypeNode,

    LockStatement,
    Block,
    EmptyStatement,
    VariableStatement,
    ExpressionStatement,
    IfStatement,
    DoStatement,
    WhileStatement,
    ForStatement,
    ForEachStatement,
    BreakStatement,
    ContinueStatement,
    ReturnStatement,
    SwitchStatement,
    ThrowStatement,
    TryStatement,
    UsingStatement,

    VariableDeclarationList,
    VariableDeclaration,
    DeconstructDeclaration,
    CaseClause,
    DefaultClause,
    CatchClause,

    PrefixUnaryExpression,
    PostfixUnaryExpression,
    NullLiteral,
    TrueLiteral,
    FalseLiteral,
    ThisLiteral,
    BaseLiteral,
    StringLiteral,
    LongLiteral,
    DoubleLiteral,
    CharLiteral,
    IntegerLiteral,
    BinaryExpression,
    ConditionalExpression,
    LambdaExpression,
    NumericLiteral,
    StringTemplateExpression,
    IsExpression,
    ParenthesizedExpression,
    ArrayCreationExpression,
    ArrayInitializerExpression,
    MemberAccessExpression,
    AnonymousObjectCreationExpression,
    AnonymousObjectProperty,
    ElementAccessExpression,
    InvocationExpression,
    NewExpression,
    CastExpression,
    NonNullExpression,
    NullSafeExpression,
    Identifier,
    DefaultExpression,
    TypeOfExpression,

    Attribute
}

interface CsNode {
    var skipEmit: Boolean
    var jNode: com.github.javaparser.ast.Node?
    var jSymbol: ResolvedDeclaration?
    val nodeType: CsSyntaxKind
    var parent: CsNode?
}

abstract class CsNodeBase : CsNode {
    override var skipEmit: Boolean = false
    override var jNode: com.github.javaparser.ast.Node? = null
    override var jSymbol: ResolvedDeclaration? = null
    override var parent: CsNode? = null
}

class CsSourceFile : CsNodeBase() {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.SourceFile
    var fileName: Path = Paths.get("file.cs")
    var usings: MutableList<CsUsingDeclaration> = ArrayList()
    var namespace: CsNamespaceDeclaration? = null
}

class CsUsingDeclaration : CsNodeBase() {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.UsingDeclaration
    var namespaceOrTypeName: String = ""
}

class CsNamespaceDeclaration : CsNodeBase() {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.NamespaceDeclaration
    var namespace: String = ""
    var declarations: MutableList<CsNamespaceMember> = ArrayList()
}

interface CsNamespaceMember : CsNode {
}

enum class CsVisibility {
    None,
    Public,
    Protected,
    Private,
    Internal
}

interface CsDocumentedElement : CsNode {
    var documentation: String?
}

interface CsAttributedElement : CsNode {
    var attributes: MutableList<CsAttribute>
}

class CsAttribute(
    var type: CsTypeNode
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.Attribute
    var indexedArguments: MutableList<CsExpression> = ArrayList()
    var namedArguments: MutableList<Pair<String, CsExpression>> = ArrayList()

    init {
        type.parent = this
    }
}

interface CsNamedElement {
    var name: String
}

// Declarations

class CsTypeParameterDeclaration : CsNodeBase(), CsNamedElement, CsNode, CsTypeReferenceType, CsTypeNode {
    override var isNullable: Boolean = false
    override var isOptional: Boolean = false
    override val nodeType: CsSyntaxKind = CsSyntaxKind.TypeParameterDeclaration
    var constraint: CsTypeNode? = null
    override var name: String = ""
}

interface CsNamedTypeDeclaration : CsNamedElement, CsDocumentedElement, CsNode, CsAttributedElement, CsClassMember,
    CsInterfaceMember,
    CsTypeReferenceType, CsNamespaceMember {
    var typeParameters: MutableList<CsTypeParameterDeclaration>
    var visibility: CsVisibility
    var partial: Boolean
}

class CsClassDeclaration : CsNodeBase(), CsNamedTypeDeclaration {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ClassDeclaration
    var baseClass: CsTypeNode? = null
    var interfaces: MutableList<CsTypeNode> = ArrayList()
    var isAbstract: Boolean = false
    var members: MutableList<CsClassMember> = ArrayList()
    override var typeParameters: MutableList<CsTypeParameterDeclaration> = ArrayList()
    override var visibility: CsVisibility = CsVisibility.None
    override var partial: Boolean = false
    override var name: String = ""
    override var documentation: String? = null
    override var attributes: MutableList<CsAttribute> = ArrayList()
}

interface CsClassMember : CsNode {
}

class CsEnumDeclaration : CsNodeBase(), CsNamedTypeDeclaration {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.EnumDeclaration
    var members: MutableList<CsEnumMember> = ArrayList()
    override var typeParameters: MutableList<CsTypeParameterDeclaration> = ArrayList()
    override var visibility: CsVisibility = CsVisibility.None
    override var partial: Boolean = false
    override var name: String = ""
    override var documentation: String? = null
    override var attributes: MutableList<CsAttribute> = ArrayList()
}

class CsEnumMember : CsNodeBase(), CsNode, CsNamedElement, CsDocumentedElement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.EnumMember
    var initializer: CsExpression? = null
    override var name: String = ""
    override var documentation: String? = null
}

class CsInterfaceDeclaration(
    override var name: String = ""
) : CsNodeBase(), CsNamedTypeDeclaration, CsInterfaceMember {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.InterfaceDeclaration
    var interfaces: MutableList<CsTypeNode> = ArrayList()
    var members: MutableList<CsInterfaceMember> = ArrayList()
    override var typeParameters: MutableList<CsTypeParameterDeclaration> = ArrayList()
    override var visibility: CsVisibility = CsVisibility.None
    override var partial: Boolean = false
    override var documentation: String? = null
    override var attributes: MutableList<CsAttribute> = ArrayList()
}

interface CsInterfaceMember : CsNode {
}

interface CsMemberDeclaration : CsNamedElement, CsDocumentedElement, CsNode {
    var visibility: CsVisibility
    var isStatic: Boolean
}

interface CsExpressionOrBlockBody : CsNode {
}

interface CsMethodDeclarationBase : CsMemberDeclaration {
    var parameters: MutableList<CsParameterDeclaration>
    var body: CsExpressionOrBlockBody?
}

class CsMethodDeclaration(
    var returnType: CsTypeNode,
    override var name: String
) : CsNodeBase(), CsMethodDeclarationBase, CsAttributedElement, CsClassMember, CsInterfaceMember {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.MethodDeclaration
    override var visibility: CsVisibility = CsVisibility.None
    var isVirtual: Boolean = false
    var isSynchronized: Boolean = false
    var isOverride: Boolean = false
    var isAbstract: Boolean = false
    var partial: Boolean = false
    override var isStatic: Boolean = false
    var typeParameters: MutableList<CsTypeParameterDeclaration> = ArrayList()
    override var parameters: MutableList<CsParameterDeclaration> = ArrayList()
    override var body: CsExpressionOrBlockBody? = null
    override var documentation: String? = null
    override var attributes: MutableList<CsAttribute> = ArrayList()

    init {
        returnType.parent = this
    }
}

class CsConstructorDeclaration : CsNodeBase(), CsMethodDeclarationBase, CsClassMember, CsAttributedElement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ConstructorDeclaration
    override var visibility: CsVisibility = CsVisibility.None
    var baseConstructorArguments: MutableList<CsExpression>? = null
    override var parameters: MutableList<CsParameterDeclaration> = ArrayList()
    override var body: CsExpressionOrBlockBody? = null
    override var isStatic: Boolean = false
    override var name: String = ""
    override var documentation: String? = null
    override var attributes: MutableList<CsAttribute> = ArrayList()
}

class CsFieldDeclaration(
    var type: CsTypeNode
) : CsNodeBase(), CsMemberDeclaration, CsClassMember, CsAttributedElement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.FieldDeclaration
    override var visibility: CsVisibility = CsVisibility.None
    var isReadonly: Boolean = false
    var isConst: Boolean = false
    var initializer: CsExpression? = null
    override var isStatic: Boolean = false
    override var name: String = ""
    override var documentation: String? = null
    override var attributes: MutableList<CsAttribute> = ArrayList()

    init {
        type.parent = this
    }
}

class CsPropertyDeclaration(
    var type: CsTypeNode
) : CsNodeBase(), CsMemberDeclaration, CsClassMember, CsInterfaceMember {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.PropertyDeclaration
    override var visibility: CsVisibility = CsVisibility.None
    var isVirtual: Boolean = false
    var isOverride: Boolean = false
    var isAbstract: Boolean = false

    var getAccessor: CsPropertyAccessorDeclaration? = null
    var setAccessor: CsPropertyAccessorDeclaration? = null
    var initializer: CsExpression? = null

    override var isStatic: Boolean = false
    override var name: String = ""
    override var documentation: String? = null
}

class CsPropertyAccessorDeclaration(
    var keyword: String,
    var body: CsExpressionOrBlockBody?
) : CsNodeBase() {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.PropertyAccessorDeclaration
}

class CsParameterDeclaration : CsNodeBase(), CsNamedElement, CsNode, CsDocumentedElement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ParameterDeclaration
    var type: CsTypeNode? = null
    var initializer: CsExpression? = null
    var params: Boolean = false
    override var name: String = ""
    override var documentation: String? = null
}

// Type System

interface CsTypeNode : CsNode, CsTypeReferenceType, CsExpression {
    var isNullable: Boolean
    var isOptional: Boolean
}

class CsUnresolvedTypeNode : CsNodeBase(), CsTypeNode {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.UnresolvedTypeNode
    var jDeclaration: ResolvedDeclaration? = null
    var jType: ResolvedType? = null
    var typeArguments: MutableList<CsTypeNode> = ArrayList()
    var resolved: CsTypeNode? = null

    override var isNullable: Boolean = false
    override var isOptional: Boolean = false
}

interface CsTypeReferenceType {
}

class CsStringTypeReference(var text: String) : CsNodeBase(), CsTypeReferenceType {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.TypeReference
}

class CsTypeReference(var reference: CsTypeReferenceType) : CsNodeBase(), CsExpression, CsTypeNode {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.TypeReference
    var typeArguments: MutableList<CsTypeNode> = ArrayList()
    override var isNullable: Boolean = false
    override var isOptional: Boolean = false
}

class CsArrayTypeNode(var elementType: CsTypeNode) : CsNodeBase(), CsTypeNode {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ArrayTypeNode
    override var isNullable: Boolean = false
    override var isOptional: Boolean = false
    init {
        elementType.parent = this
    }
}

enum class CsPrimitiveType {
    Bool,
    String,
    Double,
    Float,
    Long,
    Int,
    Short,
    SByte,
    Char,
    Void,
    Object,
    Dynamic,
    Var
}

class CsPrimitiveTypeNode(var type: CsPrimitiveType) : CsNodeBase(), CsTypeNode {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.PrimitiveTypeNode
    override var isNullable: Boolean = false
    override var isOptional: Boolean = false
}

// Expressions

interface CsExpression : CsNode, CsExpressionOrBlockBody, CsStringTemplateExpressionChunk,
    CsForStatementInitializer {}

class CsPrefixUnaryExpression(
    var operand: CsExpression,
    var operator: String
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.PrefixUnaryExpression

    init {
        operand.parent = this
    }
}

class CsPostfixUnaryExpression(
    var operand: CsExpression,
    var operator: String
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.PostfixUnaryExpression

    init {
        operand.parent = this
    }
}

class CsNullLiteral : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.NullLiteral
}

class CsBooleanLiteral(var isTrue: Boolean) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = if (isTrue) CsSyntaxKind.TrueLiteral else CsSyntaxKind.FalseLiteral
}

class CsThisLiteral : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ThisLiteral
}

class CsBaseLiteral : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.BaseLiteral
}

class CsStringLiteral(var text: String) : CsNodeBase(), CsStringTemplateExpressionChunk, CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.StringLiteral
}

class CsLongLiteral(var text: String) : CsNodeBase(), CsStringTemplateExpressionChunk, CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.LongLiteral
}

class CsDoubleLiteral(var text: String) : CsNodeBase(), CsStringTemplateExpressionChunk, CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.DoubleLiteral
}

class CsCharLiteral(var text: String) : CsNodeBase(), CsStringTemplateExpressionChunk, CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.CharLiteral
}

class CsIntegerLiteral(var text: String) : CsNodeBase(), CsStringTemplateExpressionChunk, CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.IntegerLiteral
}

class CsBinaryExpression(
    var left: CsExpression,
    var operator: String,
    var right: CsExpression
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.BinaryExpression

    init {
        left.parent = this
        right.parent = this
    }
}

class CsConditionalExpression(
    var condition: CsExpression,
    var whenTrue: CsExpression,
    var whenFalse: CsExpression
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ConditionalExpression

    init {
        condition.parent = this
        whenTrue.parent = this
        whenFalse.parent = this
    }
}

class CsLambdaExpression(
    var parameters: MutableList<CsParameterDeclaration>,
    var body: CsExpressionOrBlockBody,
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.LambdaExpression

    init {
        for (p in parameters) {
            p.parent = this
        }
        body.parent = this
    }
}

class CsNumericLiteral(var value: String) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.NumericLiteral
}

class CsStringTemplateExpression : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.StringTemplateExpression
    var chunks: MutableList<CsStringTemplateExpressionChunk> = ArrayList()
}

interface CsStringTemplateExpressionChunk {
}

class CsIsExpression(
    var expression: CsExpression,
    var type: CsTypeNode
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.IsExpression
    var newName: String? = null

    init {
        expression.parent = this
        type.parent = this
    }
}

class CsParenthesizedExpression(var expression: CsExpression) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ParenthesizedExpression
}

class CsDefaultExpression : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.DefaultExpression
    var type: CsTypeNode? = null
}

class CsArrayCreationExpression : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ArrayCreationExpression
    var type: CsTypeNode? = null
    var values: MutableList<CsExpression>? = null
    var sizeExpressions: MutableList<CsExpression?> = ArrayList()
}

class CsArrayInitializerExpression : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ArrayInitializerExpression
    var values: MutableList<CsExpression>? = null
}

class CsMemberAccessExpression(
    var expression: CsExpression,
    var member: String
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.MemberAccessExpression

    init {
        expression.parent = this
    }
}

class CsAnonymousObjectCreationExpression : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.AnonymousObjectCreationExpression
    var properties: MutableList<CsAnonymousObjectProperty> = ArrayList()
}

class CsAnonymousObjectProperty(
    var name: String,
    var value: CsExpression
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.AnonymousObjectProperty
}

class CsElementAccessExpression(
    var expression: CsExpression,
    var argumentExpression: CsExpression
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ElementAccessExpression

    init {
        expression.parent = this
        argumentExpression.parent = this
    }
}

class CsInvocationExpression(var expression: CsExpression) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.InvocationExpression
    var arguments: MutableList<CsExpression> = ArrayList()
    var typeArguments: MutableList<CsTypeNode> = ArrayList()

    init {
        expression.parent = this
    }
}

class CsNewExpression(
    var type: CsTypeNode
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.NewExpression
    var arguments: MutableList<CsExpression> = ArrayList()
}

class CsCastExpression(
    var type: CsTypeNode,
    var expression: CsExpression
) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.CastExpression

    init {
        type.parent = this
        expression.parent = this
    }
}

class CsNonNullExpression(var expression: CsExpression) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.NonNullExpression
}

class CsTypeOfExpression(var expression: CsExpression) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.TypeOfExpression

    init {
        expression.parent = this
    }
}

class CsNullSafeExpression(var expression: CsExpression) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.NullSafeExpression
}

class CsIdentifier(var text: String) : CsNodeBase(), CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.Identifier
}

// Statements

interface CsStatement : CsNode {}

class CsLockStatement(
    var expression: CsExpression,
    var body: CsBlock
) : CsNodeBase(), CsStatement, CsExpressionOrBlockBody {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.LockStatement

    init {
        expression.parent = this
        body.parent = this
    }
}

class CsBlock : CsNodeBase(), CsStatement, CsExpressionOrBlockBody {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.Block
    var statements: MutableList<CsStatement> = ArrayList()
}

class CsEmptyStatement : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.EmptyStatement
}

class CsVariableStatement(var declarationList: CsVariableDeclarationList) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.VariableStatement
}

class CsExpressionStatement(var expression: CsExpression) : CsNodeBase(), CsStatement, CsExpressionOrBlockBody {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ExpressionStatement

    init {
        expression.parent = this
    }
}

class CsIfStatement(
    var expression: CsExpression,
    var thenStatement: CsStatement,
    var elseStatement: CsStatement?
) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.IfStatement

    init {
        expression.parent = this
        thenStatement.parent = this
        elseStatement?.parent = this
    }
}

class CsDoStatement(
    var expression: CsExpression,
    var statement: CsStatement
) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.DoStatement

    init {
        expression.parent = this
        statement.parent = this
    }
}

class CsWhileStatement(
    var expression: CsExpression,
    var statement: CsStatement,
) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.WhileStatement

    init {
        expression.parent = this
        statement.parent = this
    }
}

class CsVariableDeclarationList : CsNodeBase(), CsForStatementInitializer, CsExpression {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.VariableDeclarationList
    var declarations: MutableList<CsVariableDeclaration> = ArrayList()
}

class CsVariableDeclaration(
    var type: CsTypeNode,
    var name: String,
    var deconstructNames: MutableList<String>?,
    var initializer: CsExpression?
) : CsNodeBase() {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.VariableDeclaration

    init {
        type.parent = this
        initializer?.parent = this
    }
}

class CsDeconstructDeclaration(var names: MutableList<String>) : CsNodeBase() {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.DeconstructDeclaration
}

class CsForStatement(
    var initializer: MutableList<CsForStatementInitializer>,
    var condition: CsExpression?,
    var incrementor: MutableList<CsExpression>,
    var statement: CsStatement
) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ForStatement

    init {
        for (i in initializer) {
            i.parent = this
        }
        condition?.parent = this
        for (i in incrementor) {
            i.parent = this
        }
        statement.parent = this
    }
}

interface CsForStatementInitializer : CsNode {
}

class CsForEachStatement(
    var initializer: CsForStatementInitializer,
    var expression: CsExpression,
    var statement: CsStatement
) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ForEachStatement

    init {
        initializer.parent = this
        expression.parent = this
        statement.parent = this
    }
}

class CsBreakStatement : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.BreakStatement
}

class CsContinueStatement : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ContinueStatement
}

class CsReturnStatement(
    var expression: CsExpression? = null
) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ReturnStatement
    init {
        expression?.parent = this
    }
}

class CsSwitchStatement(var expression: CsExpression) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.SwitchStatement
    var caseClauses: MutableList<CsSwitchClause> = ArrayList()
}

interface CsSwitchClause {

}

class CsCaseClause(var expression: CsExpression) : CsNodeBase(), CsSwitchClause {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.CaseClause
    var statements: MutableList<CsStatement> = ArrayList()

    init {
        expression.parent = this
    }
}

class CsDefaultClause : CsNodeBase(), CsSwitchClause {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.DefaultClause
    var statements: MutableList<CsStatement> = ArrayList()
}

class CsThrowStatement(
    var expression: CsExpression? = null
) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.ThrowStatement

    init {
        expression?.parent = this
    }
}

class CsTryStatement(var tryBlock: CsBlock) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.TryStatement
    var catchClauses: MutableList<CsCatchClause> = ArrayList()
    var finallyBlock: CsBlock? = null
}

class CsUsingStatement(var expressions: MutableList<CsExpression>, var body: CsBlock) : CsNodeBase(), CsStatement {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.UsingStatement

    init {
        for (e in expressions) {
            e.parent = this
        }
    }
}

class CsCatchClause(
    var parameter: CsParameterDeclaration,
    var block: CsBlock
) : CsNodeBase() {
    override val nodeType: CsSyntaxKind = CsSyntaxKind.CatchClause
    val whenTypeClauses: MutableList<CsTypeNode> = ArrayList()

    init {
        parameter.parent = this
        block.parent = this
    }
}