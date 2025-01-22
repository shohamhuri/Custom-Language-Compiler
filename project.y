%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lex.yy.c"
#include <stdbool.h>
#include <regex.h>
#define MAX_UNASSIGNED 50
typedef struct node {
    char* token;
    struct node *left;
    struct node *right;
} node;

typedef enum {
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_CHAR,
    TYPE_BOOL,
    TYPE_STRING,
    TYPE_INT_PTR,
    TYPE_CHAR_PTR,
    TYPE_DOUBLE_PTR,
    TYPE_FLOAT_PTR,
    TYPE_VOID,
    TYPE_NULL,
} Type;

    
typedef struct {
    Type type;
    char name[50];
} funcArgs;

typedef struct {
    char* id;
    int size;
} UnassignedVar;

typedef struct{
    char* id;
    Type type;
} variable;

typedef struct {
    char name[50];
    Type type;
    int is_function;
    int is_static;
    int is_public;
    int num_args;
    Type return_type;
    struct Symbol* next;
    funcArgs argsArray[50];
} Symbol;

typedef struct{
    struct Symbol* first;
    struct Scope* father;
} Scope;

typedef struct{
    char name[50];
    int params_size;
    bool has_type;
} func;

extern int temp_counter;
extern int label_counter;

int calculate_expression_size(node* n, int size);
int calculate_function_size(node* root, Type type, variable var[], int* varCount);
char* check_expression_3ac(node* n, func* funcs);
char* new_temp_var();
int new_label();
char* evaluate_condition(node* condition, func *funcs, int* false_label, int* true_label, int calls_counter);
char* evaluate_condition_do_while(node* condition, func *funcs, int* false_label, int* true_label, int loop_label, int calls_counter);
char* code_generator(node* root, func *funcs);
void handle_while_statement(node* while_node, func *funcs);
void handle_function(node* func_node, func *funcs);
void parse_program(node* root, func* funcs);
int check_public(node* root);
node *mknode(char* token, node *left, node *right);
void printtree(node *tree, int tabs);
node* createNode();
void yyerror(const char *msg);
int check_ptr(Type t);
int is_string_elem(node* root, Symbol* s, Scope* sc);
Type check_relational(node* n, Scope* sc);
Type check_logical(node* n, Scope *sc);
#define YYDEBUG 1
extern int yydebug;
void check_tree(node* root, Scope* sc);
bool check_assignment_types(Scope* sc, node* node);
Type stringToType(const char* str);
const char* typeToString(Type type);
bool isInteger(const char *str);
bool isFloat(const char *value);
bool isDouble(const char *value);
bool isBoolean(const char *str);
Type checkType(const char *value);
int is_numeric(Type t);
Type get_arithmetic_result_type(Type t1, Type t2);
Type get_comparison_result_type(Type t1, Type t2);
Type get_equality_result_type(Type t1, Type t2);
Type check_arithmetic(node* n, Scope* sc);
Type check_equality(node* n, Scope* sc);
Type check_expression(node* n, Scope* sc);
int is_comparable(Type type);
Scope* create_scope(Scope* father);
Symbol* create_symbol(char* name, Type type, int is_function, int is_static, int is_public, int num_args, Type return_type, funcArgs args[]);
void add_symbol(Scope* scope, Symbol* symbol);
Symbol* find_symbol_in_scope(Scope* scope, char* name);
Symbol* find_symbol(Scope* scope, char* name);
bool check_main_function(Scope* global_scope);
bool check_unique_identifier(Scope* scope);
bool compare_funcArgs(const funcArgs* a, const funcArgs* b);
bool same_header(Symbol* current, Symbol* runner);
bool check_unique_function(Scope* scope);
bool check_function_definitions(Scope* global_scope, char* function_name);
bool check_function_params(Scope* scope, char* function_name);
bool check_variable_definitions(Scope* scope, char* variable_name);
bool check_function_arguments(Scope* global_scope, char* function_name, int actual_args_count, funcArgs argsArray[]);
void extract_parameters(node* funcRoot, funcArgs argsArray[], int* num_args);
void extract_arguments(node* funcRoot, funcArgs argsArray[], int* num_args, Scope* sc);
int check_access(node* funcRoot);
int check_static(node* funcRoot);
bool check_private_not_in_scope(node* root, Scope* sc);
bool check_nonstatic_call(node* root, Scope* sc);

int temp_counter = 0;
int label_counter = 0;
int funcs_counter = 0;
func funcs[50];

%}
%union
{
	char *string;
	struct node *node_ptr;
}

%token <string> INT_VALUE CHAR_VAL DOUBLE_VAL FLOAT_VAL STRING_VAL ID
%token <string> RETURN IF ELSE WHILE FOR DO VAR ARGS PUBLIC PRIVATE STATIC NULL_ VOID BOOL_TRUE BOOL_FALSE
%token <string> BOOL CHAR DOUBLE FLOAT STRING INT
%token <string> INT_PTR CHAR_PTR DOUBLE_PTR FLOAT_PTR

%type <node_ptr> program statement expr if_expr for_init for_init2 update Declarations String_Variables String_Assignment Variables Assignment type function access_specifier parameter_list parameter id_expr arguments function_body static_op code function_body_void statement_list return_statement

%left AND OR
%left '>' GE '<' LE '=' NE EQ NOT
%left '+' '-'
%left '/' '*'
%left ';' ','
%right ASSIGN ')'
%%



program:
	code {
    	printtree($1, 1);
    	Scope* global_scope = create_scope(NULL);
	    check_tree($1, global_scope);
	    check_main_function(global_scope);
        parse_program($1, funcs);
    }
;
code: 
    function code
    {$$ = mknode("CODE",$1,$2);}
    | function {$$ = mknode("CODE",$1, NULL);}
;

function:
    /*function_header '{' function_body '}'
    { $$ = mknode("FUNC", $1, $3); }*/
    access_specifier type ID '(' ARGS parameter_list ')' static_op '{' function_body '}'
    { $$ = mknode("FUNC", mknode($3, $1, $2), mknode("", mknode("", $6, $8), $10)); }
    | access_specifier type ID '(' ')' static_op '{' function_body '}'
    { $$ = mknode("FUNC", mknode($3, $1, $2), mknode("",mknode("", NULL, $6), $8)); }
    | access_specifier VOID ID '(' ARGS parameter_list ')' static_op '{' function_body_void '}'
    { $$ = mknode("FUNC", mknode($3, $1, mknode("VOID",NULL,NULL)), mknode("", mknode("", $6, $8), $10)); }
    | access_specifier VOID ID '(' ')' static_op '{' function_body_void '}'
    { $$ = mknode("FUNC", mknode($3, $1, mknode("VOID",NULL,NULL)), mknode("",mknode("", NULL, $6), $8)); }
    | access_specifier type ID '(' ARGS parameter_list ')' static_op ';'
    { $$ = mknode("FUNC_DEF", mknode($3, $1, $2), mknode("", mknode("", $6, $8), NULL)); }
    | access_specifier type ID '(' ')' static_op ';'
    { $$ = mknode("FUNC_DEF", mknode($3, $1, $2), mknode("",mknode("", NULL, $6), NULL)); }
    | access_specifier VOID ID '(' ARGS parameter_list ')' static_op ';'
    { $$ = mknode("FUNC_DEF", mknode($3, $1, mknode("VOID",NULL,NULL)), mknode("", mknode("", $6, $8), NULL)); }
    | access_specifier VOID ID '(' ')' static_op ';'
    { $$ = mknode("FUNC_DEF", mknode($3, $1, mknode("VOID",NULL,NULL)), mknode("",mknode("", NULL, $6), NULL)); }
;
function_body:
    statement function_body
    { $$ = mknode("func_body", $1, $2); }
    | return_statement
    { $$ = mknode("return_statement",$1,NULL); }
;
 

function_body_void:
   statement function_body_void
   { $$ = mknode("func_body", $1, $2); }
   | statement
   { $$ = mknode("func_body", $1, NULL); }
   | {$$ = NULL;}
;

return_statement:
    RETURN expr ';'
    { $$ = mknode("RETURN",$2,NULL); }
    | RETURN ';'
    { $$ = mknode("RETURN VOID", NULL, NULL); }
;

static_op:
    ':' STATIC { $$ = mknode("STATIC",NULL,NULL) ;}
    | {$$ =  mknode("NONSTATIC",NULL,NULL) ;} 
;

statement_list:
    statement statement_list
    { $$ = mknode("statement_list",$1,$2); }
    | statement
    { $$ = mknode("statement_list",$1,NULL); }
;

statement:
    function
    | if_expr
    { $$ = mknode("if_expr",$1,NULL); }
    | if_expr ELSE statement
    { $$ = mknode("if_expr", $1, mknode("else-statement",$3,NULL)); }
    | WHILE '(' expr ')' statement
    { $$ = mknode("WHILE", $3, mknode("while-statement",$5,NULL)); }
    | DO statement WHILE '(' expr ')' ';'
    { $$ = mknode("do-statement", $2, mknode("WHILE",$5,NULL)); }
    | FOR '(' for_init ';' expr ';' update ')' statement
    { $$ = mknode("FOR", mknode("INIT", $3, mknode("COND-UPDATE-FOR", $5, $7)), mknode("STATEMENT", $9,NULL)); }
    | Declarations
    { $$ = $1; }
    | '*' ID ASSIGN expr ';'
    { $$ = mknode("ASSIGN_PTR", mknode("VAR", mknode(strdup($2), NULL, NULL), NULL), $4); }
    | Assignment ';'
    { $$ = mknode("",$1,NULL) ;}
    | STRING String_Assignment //duplicate might cause problems ;P
    { $$ = $2; }
    | String_Assignment ';'
    { $$ = $1; }
    | return_statement
    { $$ = mknode("return_statement", $1, NULL); }
    | '{' statement_list '}'
    { $$ = mknode("BRACKETS",$2,NULL); }
    | '{' '}'
    { $$ = mknode("", NULL, NULL); }
    | expr ';'
    { $$ = $1; }
;

if_expr:
    IF '(' expr ')' statement
    { $$ = mknode("IF", $3, mknode("if_statement",$5,NULL)); }
;

for_init:
    Assignment
    { $$ = mknode("FOR_INIT",$1,NULL); }
    | Assignment ',' for_init2
    { $$ = mknode("FOR_INIT", $1, $3); }
    | String_Assignment
    { $$ = mknode("FOR_INIT",$1,NULL); }
    | String_Assignment ',' for_init2
    { $$ = mknode("FOR_INIT", $1, $3); }
    | /*empty*/
    {$$ = mknode("",NULL,NULL);}
;

for_init2:
    Assignment
    { $$ = mknode("FOR_INIT",$1,NULL); }
    | Assignment ',' for_init2
    { $$ = mknode("FOR_INIT", $1, $3); }
    | String_Assignment
    { $$ = mknode("FOR_INIT",$1,NULL); }
    | String_Assignment ',' for_init2
    { $$ = mknode("FOR_INIT", $1, $3); }
;


expr:
    ID '(' arguments ')'  // function call
    { $$ = mknode("CALL", mknode($1,NULL,NULL), $3); }
    |ID '(' ')'  // function call
    { $$ = mknode("CALL", mknode($1,NULL,NULL), NULL); }
     | '+' expr
    { $$ = mknode("+",$2,NULL); }
    | '-' expr
    { $$ = mknode("-",$2,NULL); }
    //numeric
    | expr '+' expr 
    { $$ = mknode("+", $1, $3); }
    | expr '-' expr
    { $$ = mknode("-", $1, $3); }
    | expr '*' expr
    { $$ = mknode("*", $1, $3); }
    | expr '/' expr
    { $$ = mknode("/", $1, $3); }
    | expr EQ expr
    { $$ = mknode("==", $1, $3); }
    | expr NE expr
    { $$ = mknode("!=", $1, $3); }
    | expr '>' expr
    { $$ = mknode(">", $1, $3); }
    | expr '<' expr
    { $$ = mknode("<", $1, $3); }
    | expr GE expr
    { $$ = mknode(">=", $1, $3); }
    | expr LE expr
    { $$ = mknode("<=", $1, $3); }
    | NOT expr
    { $$ = mknode("!", $2, NULL); }
    | expr AND expr
    { $$ = mknode("&&", $1, $3); }
    | expr OR expr
    { $$ = mknode("||", $1, $3); }
    | ID id_expr
    { $$ = mknode($1, $2, NULL); }
    | '&' ID id_expr
    { $$ = mknode("&", mknode($2, NULL, NULL), $3); }
    | '*' expr
    { $$ = mknode("*", $2, NULL); }
    | BOOL_TRUE
    { $$ = mknode("TRUE", NULL, NULL); }
    | BOOL_FALSE
    { $$ = mknode("FALSE", NULL, NULL); }
    | INT_VALUE
    { $$ = mknode($1, NULL, NULL) ;}
    | DOUBLE_VAL
    { $$ = mknode($1, NULL, NULL); }
    | FLOAT_VAL
    { $$ = mknode($1, NULL, NULL); }
    | STRING_VAL
    { $$ = mknode($1, NULL, NULL); }
    | CHAR_VAL
    { $$ = mknode($1, NULL, NULL); }
    | NULL_
    { $$ = mknode("NULL", NULL, NULL); }
    | '(' expr ')'
    { $$ = mknode("expr",$2, NULL);}
    | '|' expr '|'
    { $$ = mknode("STR_LEN",$2,NULL);}
;

id_expr:
    '[' expr ']'  // accessing array element
    { $$ = mknode("ARRAY_ELEM", $2, NULL); }
    | /*empty*/
    { $$ = mknode("ID",NULL,NULL); }

;

Declarations:
    VAR type ':' Variables ';'
    { $$ = mknode("DECLARE", $2, $4); }
|   STRING String_Variables ';'
    { $$ = mknode("DECLARE", mknode("STRING", NULL, NULL), $2); }
;

/*
string a[30] <- "yossi", b[100] <- "moshe";
*/
String_Variables:
    ID '[' expr ']'
    { $$ = mknode("STRING_VAR", mknode($1, mknode("[", $3, mknode("]", NULL, NULL)), NULL), NULL); }
    | ID '[' expr ']' ',' String_Variables
    { $$ = mknode("STRING_VAR", mknode($1, mknode("[", $3, mknode("]", NULL, NULL)), NULL), $6); }
    | String_Assignment
    { $$ = mknode("STRING_ASSIGNMENT", $1, NULL); }
    | String_Assignment ',' String_Variables
    { $$ = mknode("STRING_ASSIGNMENT", $1, $3); }
;

String_Assignment:
    ID '[' expr ']' ASSIGN expr
    { $$ = mknode("STRING_ASSIGN", mknode($1,mknode("INDEX",$3,NULL),NULL), $6); }
;

Variables:
    Assignment
    { $$ = $1; }
    | ID
    { $$ = mknode("VAR", mknode($1,NULL,NULL), NULL); }
    | Assignment ',' Variables
    { $$ = mknode("SEQUENCE", $1, $3); }
    | ID ',' Variables
    { $$ = mknode("VAR", mknode($1, NULL, NULL), $3); }
;

Assignment:
    ID ASSIGN expr
    { $$ = mknode("ASS", mknode($1,NULL,NULL), $3); }
    | ID '[' expr ']' ASSIGN expr ';'
    { $$ = mknode("ASSIGN_ARRAY_ELEM", mknode($1, mknode("INDEX",$3,NULL),NULL), $6); }
    
;

type:
    BOOL
    { $$ = mknode("BOOL", NULL, NULL); }
    | CHAR
    { $$ = mknode("CHAR", NULL, NULL); }
    | INT
    { $$ = mknode("INT", NULL, NULL); }
    | DOUBLE
    { $$ = mknode("DOUBLE", NULL, NULL); }
    | FLOAT
    { $$ = mknode("FLOAT", NULL, NULL); }
    | INT_PTR
    { $$ = mknode("INT_PTR", NULL, NULL); }
    | CHAR_PTR
    { $$ = mknode("CHAR_PTR", NULL, NULL); }
    | DOUBLE_PTR
    { $$ = mknode("DOUBLE_PTR", NULL, NULL); }
    | FLOAT_PTR
    { $$ = mknode("FLOAT_PTR", NULL, NULL); }
;

update:
    expr
    | Assignment
    | /*empty*/
    { $$ = NULL; }

;

/* arguments to call a function */
arguments:
    expr ',' arguments
    { $$ = mknode("ARGS", $1, $3); }
    | expr
    { $$ = mknode("ARGS", $1, NULL); }
;

access_specifier:
    PUBLIC
    { $$ = mknode("PUBLIC", NULL, NULL); }
    | PRIVATE
    { $$ = mknode("PRIVATE", NULL, NULL); }
;



parameter_list:
type ':' parameter
    { $$ = mknode("PARAMETER_LIST", mknode("PARAMETERS", $1, $3), NULL); }

| type ':' parameter ';' parameter_list
{$$ = mknode ("PARAMETER_LIST" , mknode("PARAMETERS",$1,$3) , $5);}

;

parameter:
    ID {$$ = mknode("PARAM", mknode($1,NULL,NULL), NULL); }
    |
    ID ',' parameter
    { $$ = mknode("PARAM", mknode($1,NULL,NULL), $3); }
;

%%

void yyerror(const char *msg) {
    fprintf(stderr, "Parser error at line %d: %s\n", yylineno, msg);
    exit(1);
}

int main() {
    
    yydebug = 1;
    return yyparse();
    
    return 0;
}

node *mknode(char* token, node *left, node *right) {
    node *newNode = (node *)malloc(sizeof(node));
    char *newStr = (char *)malloc(strlen(token) + 1);
    strcpy(newStr, token);
    newNode->left = left;
    newNode->right = right;
    newNode->token = newStr;
    return newNode;
}

void printTabs(int numOfTabs) {
    for (int i = 0; i < numOfTabs; i++) {
        printf("\t");
    }
}

void printtree(node *tree, int tabs) {
    if (tree == NULL) return;

    printTabs(tabs);
    printf("(%s", tree->token);

    if (tree->left != NULL || tree->right != NULL) {
        printf("\n");

        if (tree->left != NULL) {
            printtree(tree->left, tabs + 1);
        } else {
            printTabs(tabs + 1);
        }

        if (tree->right != NULL) {
            printtree(tree->right, tabs + 1);
        }

        printTabs(tabs);
    }

    printf(")\n");
}


Scope* create_scope(Scope* father) {
    Scope* new_scope = (Scope*)malloc(sizeof(Scope));
    new_scope->father = father;
    new_scope->first = NULL;
    return new_scope;
}

Symbol* create_symbol(char* name, Type type, int is_function, int is_static, int is_public, int num_args, Type return_type, funcArgs args[]) {
    Symbol* new_symbol = (Symbol*)malloc(sizeof(Symbol));
    strcpy(new_symbol->name, name);
    new_symbol->type = type;
    new_symbol->is_function = is_function;
    new_symbol->is_static = is_static;
    new_symbol->is_public = is_public;
    new_symbol->num_args = num_args;
    new_symbol->return_type = return_type;
    new_symbol->next = NULL;

    if(is_function){
        memcpy(new_symbol->argsArray, args, num_args * sizeof(funcArgs));
    }
    return new_symbol;
}

void add_symbol(Scope* scope, Symbol* symbol) {
    symbol->next = scope->first;
    scope->first = symbol;
}
Symbol* find_symbol_in_scope(Scope* scope, char* name) {
        Symbol* current_symbol = scope->first;
        while (current_symbol != NULL) {
            if (strcmp(current_symbol->name, name) == 0) {
                return current_symbol;
            }
            current_symbol = current_symbol->next;
        }
    return NULL;
}

Symbol* find_symbol(Scope* scope, char* name) {
    Scope* current_scope = scope;
    while (current_scope != NULL) {
        Symbol* current_symbol = current_scope->first;
        while (current_symbol != NULL) {
            if (strcmp(current_symbol->name, name) == 0) {
                return current_symbol;
            }
            current_symbol = current_symbol->next;
        }
        current_scope = current_scope->father;
    }
    return NULL;
}

// Semantic analysis checks
bool check_main_function(Scope* global_scope) {
    Symbol* main_func = find_symbol(global_scope, "main");
    if (main_func == NULL) {
        printf("Error: main function is missing.\n");
        return false;
    }
    //printf("%d, %d, %d, %d, %s\n",main_func->is_function,main_func->is_static, main_func->is_public, main_func->num_args, typeToString(main_func->return_type));
    if (!(main_func->is_function && main_func->is_static && main_func->is_public && main_func->num_args == 0 && main_func->return_type == TYPE_VOID)) {
        printf("Error: main function must be public static void and take no arguments.\n");
        return false;
    }
    return true;
}

bool check_unique_identifier(Scope* scope) {
    Symbol* current = scope->first;
    while (current != NULL) {
        Symbol* runner = current->next;
        while (runner != NULL) {
            if (strcmp(current->name, runner->name) == 0) {
                printf("Error: Duplicate name '%s' in the same scope.\n", current->name);
                return false;
            }
            runner = runner->next;
        }
        current = current->next;
    }
    return true;
}


bool compare_funcArgs(const funcArgs* a, const funcArgs* b) {

    if (a == NULL || b == NULL) {
        return a == b; //both must be NULL to be considered equal
    }
    return (a->type == b->type) && (strcmp(a->name, b->name) == 0);
}


bool same_header(Symbol* current, Symbol* runner) {
    if (current->type != runner->type) {
        return false;
    }
    if (current->is_static != runner->is_static) {
        return false;
    }
    if (current->is_public != runner->is_public) {
        return false;
    }
    if (current->num_args != runner->num_args) {
        return false;
    }
    for (int i = 0; i < current->num_args; ++i) {
        if (i >= runner->num_args || !compare_funcArgs(&current->argsArray[i], &runner->argsArray[i])) {
            return false;
        }
    }

    if (runner->num_args > current->num_args) {
        return false;
    }

    return true;
}

bool check_unique_function(Scope* scope) {
    Symbol* current = scope->first;

    while (current != NULL) {
        Symbol* runner = current->next;
        while (runner != NULL) {
            
            //if the function was implemented twice (can be same name if the return type of one is NULL - which means it was only defined)
            if (strcmp(current->name, runner->name) == 0 && runner->return_type != TYPE_NULL) {
                printf("Error: Duplicate function '%s' in the same scope.\n", current->name);
                return false;
            }
            else if (strcmp(current->name, runner->name) == 0 && runner->return_type == TYPE_NULL){
                //if the runner is a variable return false always
                if(runner->is_function == 0){
                    printf("Error: Duplicate identifier '%s' in the same scope.\n", current->name);
                    return false;
                }//if the headers of the function definition and implementation dont match
                else if(!same_header(current,runner)){
                    printf("Error: function definition doesn't match function implementation '%s'.\n", current->name);
                    return false;
                }
                
            }
            runner = runner->next;
        }
        current = current->next;
    }
    return true;
}

bool check_function_definitions(Scope* global_scope, char* function_name) {
    Symbol *s = find_symbol(global_scope, function_name);
    if (s == NULL || s->is_function == 0) {
        printf("Error: Function '%s' is used before it is defined.\n", function_name);
        return false;
    }
    return true;
}
bool check_function_implementation(Scope* sc, char* function_name){
    Symbol *s = find_symbol(sc, function_name);
    if(s->is_function == 1 && s->return_type == TYPE_NULL){
        printf("Error: Function '%s' is missing implementation.\n", function_name);
        return false;
    }
}

bool check_variable_definitions(Scope* scope, char* variable_name) {
    Symbol *s = find_symbol(scope, variable_name);
    if (s == NULL || s->is_function == 1) {
        printf("Error: Variable '%s' is used before it is defined.\n", variable_name);
        return false;
    }
    return true;
}

bool check_function_arguments(Scope* global_scope, char* function_name, int actual_args_count, funcArgs argsArray[]) {
    Symbol* function = find_symbol(global_scope, function_name);
    if (function == NULL) return false;

    if (function->num_args != actual_args_count) {
        printf("Error: Function '%s' called with incorrect number of arguments.\n", function_name);
        return false;
    }
    for(int i = 0;i < function->num_args; i++){
        if(function->argsArray[i].type != argsArray[i].type){
            printf("Error: Function call '%s' arguments don't match.\n", function_name);
            return false;
        }
    }
    return true;
}

int count_parameters_size(node* funcRoot){
    int total_size = 0;
    
    funcRoot = funcRoot->right->left->left;
    if(funcRoot == NULL)
        return 0;
    do{
        node* param = funcRoot->left;
        Type t = stringToType(param->left->token);
        while(param->right != NULL){
            param = param->right;
            total_size += get_data_type_size(t);
        }
        funcRoot = funcRoot->right;
    } while(funcRoot != NULL);
    return total_size;
}

void add_parameters_var(node* funcRoot, variable var[], int * varCount){
    funcRoot = funcRoot->right->left->left;
    if(funcRoot == NULL)
        return;
    do{
        node* param = funcRoot->left;
        Type t = stringToType(param->left->token);
        while(param->right != NULL){
            add_var(var, varCount, param->right->left->token, t);
            param = param->right;
        }
        funcRoot = funcRoot->right;
    } while(funcRoot != NULL);
}

void extract_parameters(node* funcRoot, funcArgs argsArray[], int* num_args){
    *num_args = 0;
    funcRoot = funcRoot->right->left->left;
    if(funcRoot == NULL)
        return;
    do{
        node* param = funcRoot->left;
        Type t = stringToType(param->left->token);
        while(param->right != NULL){
            param = param->right;
            strcpy(argsArray[*num_args].name, param->left->token);
            argsArray[*num_args].type = t;
            (*num_args)++;
        }
        funcRoot = funcRoot->right;
    } while(funcRoot != NULL);
}
void extract_arguments(node* funcRoot, funcArgs argsArray[], int* num_args, Scope* sc){
    *num_args = 0;
    funcRoot = funcRoot->right;
    if(funcRoot == NULL)
        return;
    
    do{
        node* param = funcRoot->left;
        Type t = check_expression(param, sc);
        argsArray[*num_args].type = t;
        (*num_args)++;
        
        funcRoot = funcRoot->right;
    } while(funcRoot != NULL);
}
int check_access(node* funcRoot){
    if(!strcmp(funcRoot->left->left->token, "PUBLIC"))
        return 1;
    return 0;
}

int check_static(node* funcRoot){
    funcRoot = funcRoot->right->left->right;
    if(funcRoot == NULL)
        return;
    if(!strcmp(funcRoot->token,"STATIC")){
        return 1;
    }
    return 0;
}

bool check_private_not_in_scope(node* root, Scope* sc){
      if (root == NULL) {
        return false; 
    }
    if (strcmp(root->token, "CALL") == 0){
        Symbol *s = find_symbol(sc, root->left->token);
        if(s != NULL && s->is_public == 0){
            Symbol *s = find_symbol_in_scope(sc, root->left->token);
            if(s == NULL){
                printf("Error: Can't call a private function %s from out of the scope.\n", root->left->token);
                return true;
            }
        }
    }
    return check_private_not_in_scope(root->left, sc) ||
           check_private_not_in_scope(root->right, sc);
}

bool check_nonstatic_call(node* root, Scope* sc){
    if (root == NULL) {
        return false; 
    }
    if (strcmp(root->token, "CALL") == 0){
        Symbol *s = find_symbol(sc, root->left->token);
        if(s != NULL && s->is_static == 0){
            printf("Error: Can't call a nonstatic function from a static function.\n");
            return true;
        }
    }
    return check_nonstatic_call(root->left, sc) ||
           check_nonstatic_call(root->right, sc);
}


// if return false, no error

// Function to check the type of an expression
/*code: 
    function code
       {$$ = mknode("CODE",$1,$2);}
    | function 
       {$$ = mknode("CODE",$1, NULL);}*/

bool check_ptr_assignment(Type left_type, Type right_type) {
    
    if (left_type == TYPE_INT_PTR && right_type == TYPE_INT) {
        return true;
    } 
    else if (left_type == TYPE_DOUBLE_PTR && right_type == TYPE_DOUBLE) {
        return true;
    } 
    else if (left_type == TYPE_FLOAT_PTR && right_type == TYPE_FLOAT) {
        return true;
    } 
    else if (left_type == TYPE_CHAR_PTR && right_type == TYPE_CHAR) {
        return true;
    }
    else if(right_type == TYPE_NULL){
        return true;
    }
    return false;
}

void check_statement(node* root, Scope* sc){
    
    if (strcmp(root->token, "DECLARE") == 0) {
        Type t = stringToType(root->left->token);
        
        node* varNode = root;
        
        while(varNode->right != NULL){
            varNode = varNode->right;
            
            if(strcmp(varNode->token, "VAR") == 0){
                Symbol* var = create_symbol(varNode->left->token, t, 0, 0, 0, 0, TYPE_NULL, NULL);
                
                add_symbol(sc, var);
                if (!check_unique_identifier(sc)) {
                    exit(1); //exit if there's a duplicate variable
                }
            }
            /*| '&' ID id_expr
    { $$ = mknode("&", mknode($2, NULL, NULL), $3); }*/
            else if (strcmp(varNode->token,"ASS") == 0){
                int flag = 0;
                Type var_t;
                if(strcmp(varNode->right->token, "&") == 0){
                    flag = 1;
                    Symbol* s = find_symbol(sc, varNode->right->left->token);
                    
                    if(!(s != NULL && (is_numeric(s->type) || is_string_elem(varNode->right,s, sc) || s->type == TYPE_CHAR))){
                        printf("Error: The address-of operator '&' can only be applied to variables of type int, float, double, char, or string element.\n");
                        exit(1);
                    }
                    
                    if(is_string_elem(varNode->right,s,sc)){
                        var_t = TYPE_CHAR;
                    }
                    else{
                        var_t = s->type;
                    }
                    if(!check_ptr(t)){
                        printf("Error: Can't assign address to a non pointer\n");
                        exit(1);
                    }
                }
                else{
                    var_t = check_expression(varNode->right, sc);
                }
                
                if(!(var_t == t)  && !check_ptr(t)){
                    printf("Variable type is: '%s' and a type %s was assigned to it\n", typeToString(t), typeToString(var_t));
                    exit(1);
                }
                if(check_ptr(t) && !check_ptr_assignment(t,var_t)){
                    printf("Variable type is: '%s' and a type %s was assigned to it\n", typeToString(t), typeToString(var_t));
                    exit(1);
                }
                else if(check_ptr(t) && flag == 0 && var_t != TYPE_NULL){
                    printf("Error: Can only point to an address of a variable\n");
                    exit(1);
                }
                Symbol* var = create_symbol(varNode->left->token, t, 0, 0, 0, 0, TYPE_NULL, NULL);
                add_symbol(sc, var);
                if (!check_unique_identifier(sc)) {
                    exit(1); //exit if there's a duplicate variable
                }
            }
            else if(strcmp(varNode->token, "SEQUENCE") == 0){
                if(strcmp(varNode->left->token, "ASS") == 0){
                    Symbol* var = create_symbol(varNode->left->left->token, t, 0, 0, 0, 0, TYPE_NULL, NULL);
                    add_symbol(sc, var);
                    Type var_t = check_expression(varNode->left->right, sc);
                    if(!(var_t == t)  && !check_ptr(t)){
                        printf("Variable type is: '%s' and a type %s was assigned to it\n", typeToString(t), typeToString(check_expression(varNode->right, sc)));
                        exit(1);
                    }
                    if(check_ptr(t) && !check_ptr_assignment(t,var_t)){
                        printf("Variable type is: '%s' and a type %s was assigned to it\n", typeToString(t), typeToString(var_t));
                        exit(1);
                    }
                    if (!check_unique_identifier(sc)) {
                        exit(1); //exit if there's a duplicate variable
                    }
                }
            }
            
        }    
        if (strcmp(root->left->token, typeToString(TYPE_STRING)) == 0){
            
            varNode = root;
            while(varNode->right != NULL){
                varNode = varNode->right;
                if(strcmp(varNode->token, "STRING_ASSIGNMENT") == 0){
                    if(check_expression(varNode->left->left->left->left, sc) != TYPE_INT){
                        printf("Error: Index type must be of type INT.\n");
                        exit(1);
                    }
                    Symbol* str = create_symbol(varNode->left->left->token, TYPE_STRING, 0, 0, 0, 0, TYPE_NULL, NULL);
                    add_symbol(sc, str);
                    
                    if (!check_unique_identifier(sc)) {
                        exit(1);
                    }// STRING DECLARATION CAN HAVE ONLY STRING ASSIGNMENT
                   
                    if(check_expression(varNode->left->right, sc) != TYPE_STRING){
                        printf("Error: value must be a STRING type, %s type was given.\n", typeToString(check_expression(varNode->left->right, sc)));
                        exit(1);
                    }
                }
                else if(strcmp(varNode->token, "STRING_VAR") == 0){
                   
                    if(check_expression(varNode->left->left->left, sc) != TYPE_INT){
                        printf("Error: Index type must be of type INT.\n");
                        exit(1);
                    }
                    Symbol* str = create_symbol(varNode->left->token, TYPE_STRING, 0, 0, 0, 0, TYPE_NULL, NULL);
                    add_symbol(sc, str);
                    if (!check_unique_identifier(sc)) {
                        exit(1);
                    }
                }
            }
        }
    } else if (strcmp(root->token, "CALL") == 0) {
  
        if (!check_function_definitions(sc, root->left->token)) {
            exit(1);
        }
        int num_args = 0;
        funcArgs argsArray[50];
        extract_arguments(root, argsArray, &num_args, sc);
        
        if (!check_function_arguments(sc, root->left->token, num_args, argsArray)) {
            exit(1);
        }
    } else if (strcmp(root->token, "WHILE") == 0) {
       
        if (check_expression(root->left, sc) != TYPE_BOOL) {
            printf("Error: Condition in '%s' is not a boolean expression.\n", root->token);
            exit(1);
        }
        Scope* childScope = create_scope(sc);
        check_statement(root->right->left, childScope);
    } else if(strcmp(root->token,"FOR") == 0){
     
        if (check_expression(root->left->right->left, sc) != TYPE_BOOL) {
            printf("Error: Condition in '%s' is not a boolean expression.\n", root->token);
            exit(1);
        }
        
        Scope* childScope = create_scope(sc);
        check_statement(root->right->left, childScope);
    } else if (strcmp(root->token, "do-statement") == 0) {
       
        if (check_expression(root->right->left, sc) != TYPE_BOOL) {
        printf("Error: Condition in '%s' is not a boolean expression.\n", root->token);
        exit(1);
        }
        Scope* childScope = create_scope(sc);
        check_statement(root->left, childScope);
    } else if(strcmp(root->token, "if_expr") == 0){
     
        if (check_expression(root->left->left, sc) != TYPE_BOOL) {
            printf("Error: Condition in '%s' is not a boolean expression.\n", root->token);
            exit(1);
        }
        Scope* childScopeIf = create_scope(sc);
        check_statement(root->left->right->left, childScopeIf);
        if(root->right != NULL){
            Scope* childScopeElse = create_scope(sc);
            check_statement(root->right->left, childScopeElse);
        }
    } else if (strcmp(root->token, "ASS") == 0) {
       
        if (!check_assignment_types(sc, root)) {
            exit(1); //exit if the assignment types are incorrect
        }
    } else if(strcmp(root->token, "ASSIGN_ARRAY_ELEM") == 0){
      
         if(check_expression(root->left->left->left, sc) != TYPE_INT){
            printf("Error: Index type must be of type INT.\n");
            exit(1);
        }
        Symbol* str = find_symbol(sc, root->left->token);
        if (str == NULL) {
            printf("Error: Variable '%s' is not defined.\n", root->left->token);
            exit(1);
        }
        Type rightType = check_expression(root->right, sc);
        if (rightType != TYPE_CHAR) {
            printf("Variable type expects a char and type %s was assigned to it\n", typeToString(rightType));
            exit(1);
        }
    } else if (strcmp(root->token, "*") == 0 && root->right == NULL) { //dereference operator
      
        Symbol* s = find_symbol(sc, root->left->token);
        
        if(!(s != NULL && check_ptr(s->type))){
            printf("Error: Invalid type for dereference operation (not pointer type).\n");
            exit(1);
        } 
    } else if (strcmp(root->token, "&") == 0) { //address of operator
    
        Symbol* s = find_symbol(sc, root->left->token);
        if(!(s != NULL && (is_numeric(s->type) || is_string_elem(root,s, sc) || s->type == TYPE_CHAR))){
            printf("Error: The address-of operator '&' can only be applied to variables of type int, float, double, char, or string element.\n");
            exit(1);
        } 
    } else if(strcmp(root->token,"BRACKETS") == 0){
       
        Scope* childScope = create_scope(sc);
        check_statement(root->left, childScope);
        
    } else if(strcmp(root->token, "statement_list") == 0){
        
        node* statement_list = root;
        do{
            
            check_statement(statement_list->left,sc);
            statement_list = statement_list->right;
        }
        while(statement_list != NULL);
        /*String_Assignment:
    ID '[' expr ']' ASSIGN expr
    { $$ = mknode("STRING_ASSIGN", mknode($1,mknode("INDEX",$3,NULL),NULL), $6); }
;
*/
    } else if(strcmp(root->token, "STRING_ASSIGN") == 0){
        Symbol* s = find_symbol(sc, root->left->token);
        if(s == NULL){
            printf("Error: Variable '%s' is not defined.\n", root->token);
            exit(1);
        }
        if(s->type != TYPE_STRING){
            printf("Can't access array element of a non string identifier\n");
            exit(1);
        }
        if(check_expression(root->left->left->left, sc) != TYPE_INT){
            printf("Error: Index type must be of type INT.\n");
            exit(1);
        }
        if(check_expression(root->right, sc) != TYPE_CHAR){
            printf("Error: value must be a CHAR type, %s type was given.\n", typeToString(check_expression(root->right, sc)));
            exit(1);
        }
    }else if(root->left != NULL && strcmp(root->left->token, "ARRAY_ELEM") == 0){
        check_expression(root,sc);
    }else{
        if(strcmp(root->token, "") == 1){
            check_expression(root,sc);
        }
        else//might cause bugs*******
            if(root->left != NULL)
                check_statement(root->left, sc);
    }
}



void check_tree(node* treeRoot, Scope* sc) {
	 if (treeRoot == NULL) return;
     node* root = treeRoot->left;
	 if (strcmp(root->token, "FUNC") == 0) {
    
        
        
        // Assume node->left is the function name and node->right is the return type and args
        Scope* childScope = create_scope(sc);
        
        Type funcType = stringToType(root->left->right->token);
        
        node* funcReturn = root;
        
        while(funcReturn->right != NULL && (strcmp(funcReturn->token, "func_body") != 0 && strcmp(funcReturn->token, "RETURN VOID") != 0)){
            funcReturn = funcReturn->right;
        }
        int num_args = 0;
        funcArgs argsArray[50];
        if(root->right->left->left != NULL){
            extract_parameters(root, argsArray, &num_args);
            for(int i = 0; i< num_args;i++){ 
                Symbol* param = create_symbol(argsArray[i].name,argsArray[i].type,0,0,0,0,TYPE_NULL,NULL);
                add_symbol(childScope,param); }
        }

        int i = 0;
        while(funcReturn != NULL && strcmp(funcReturn->token, "func_body") == 0){
            i++;
           
            node* statement = funcReturn;
           
            if(strcmp(statement->left->token,"FUNC") == 0){
                check_tree(statement, childScope);
            }
            else
                check_statement(statement->left, childScope);
            if(funcReturn->right == NULL)
                break;
            funcReturn = funcReturn->right;
        }
        
        Type returnType = TYPE_VOID;
        if(funcReturn->left != NULL && strcmp(funcReturn->left->token, "return_statement") == 0){
            funcReturn = funcReturn->left;
        }
        
        
        if(strcmp(funcReturn->token,"return_statement") == 0){
            if(strcmp(funcReturn->left->token, "RETURN_VOID") == 0 && funcType != TYPE_VOID){
                    printf("Error: Function of type %s must return a %s value.\n", typeToString(funcType), typeToString(funcType));
                    exit(1);                              
            }
            else if(strcmp(funcReturn->left->token, "RETURN") == 0 && funcType == TYPE_VOID){
                    printf("Error: Function of type %s can't return a value.\n", typeToString(funcType));
                    exit(1);             
            }
            else if(strcmp(funcReturn->left->token, "RETURN") == 0 && funcType != TYPE_VOID){
                returnType = check_expression(funcReturn->left->left, childScope);
            }
            if(returnType != funcType){
                printf("Error: Function type %s does not match return type %s.\n", typeToString(funcType),typeToString(returnType));
                exit(1);
        }
        }
        
      
        
        int is_static = check_static(root);
        int is_pub = check_public(root);
        if(is_pub == 1){
            if(check_private_not_in_scope(root->right->right, sc)){
                exit(1);
            }
        }

        Symbol* func = create_symbol(root->left->token, funcType, 1, is_static, is_pub, num_args, returnType, argsArray);
        
        add_symbol(sc, func);
        if(is_static == 1){
            if(check_nonstatic_call(root->right->right, sc))
                exit(1);
        }
        if (!check_unique_function(sc)) {
            exit(1);
        }
    } else if (strcmp(root->token, "FUNC_DEF") == 0) {
        
        Type funcType = stringToType(root->left->right->token);
        int num_args = 0;
        funcArgs argsArray[50];
        
        extract_parameters(root, argsArray, &num_args);
        int is_static = check_static(root);
        int is_pub = check_public(root);

        Symbol* func = create_symbol(root->left->token, funcType, 1, is_static, is_pub, num_args, TYPE_NULL, argsArray);
        
        add_symbol(sc, func);
        if (!check_unique_identifier(sc)) {
            exit(1); //exit if there's a duplicate function
        }
    } 
    check_tree(treeRoot->right, sc);
}
bool check_assignment_types(Scope* sc, node* n) {
    node* left = n->left;
    node* right = n->right;
    
    Symbol* left_var = find_symbol(sc, left->token);
    if (left_var == NULL) {
        printf("Error: Variable '%s' is not defined.\n", left->token);
        return false;
    }

    if(!check_ptr(left_var->type) && strcmp(right->token,"NULL") == 0) {
        printf("Error: Type mismatch in assignment to '%s', can't assign NULL to non pointer.\n", left->token);
        return false;
    }
    Type rightType = check_expression(right, sc);
    if (left_var->type != rightType && !check_ptr(left_var->type)) {
        printf("Variable type is: '%s' and a type %s was assigned to it\n", typeToString(left_var->type), typeToString(rightType));
        return false;
    }
    if(check_ptr(left_var->type) && !check_ptr_assignment(left_var->type,rightType)){
        printf("Variable type is: '%s' and a type %s was assigned to it\n", typeToString(left_var->type), typeToString(rightType));
        return false;
    }

    return true;
}


Type stringToType(const char* str) {
    if (strcmp(str, "INT") == 0) return TYPE_INT;
    if (strcmp(str, "FLOAT") == 0) return TYPE_FLOAT;
    if (strcmp(str, "DOUBLE") == 0) return TYPE_DOUBLE;
    if (strcmp(str, "CHAR") == 0) return TYPE_CHAR;
    if (strcmp(str, "BOOL") == 0) return TYPE_BOOL;
    if (strcmp(str, "INT_PTR") == 0) return TYPE_INT_PTR;
    if (strcmp(str, "CHAR_PTR") == 0) return TYPE_CHAR_PTR;
    if (strcmp(str, "DOUBLE_PTR") == 0) return TYPE_DOUBLE_PTR;
    if (strcmp(str, "FLOAT_PTR") == 0) return TYPE_FLOAT_PTR;
    if (strcmp(str, "VOID") == 0) return TYPE_VOID;
    if (strcmp(str, "NULL_") == 0) return TYPE_NULL;
    return TYPE_STRING;
}

const char* typeToString(Type type) {
    switch (type) {
        case TYPE_INT: return "INT";
        case TYPE_FLOAT: return "FLOAT";
        case TYPE_DOUBLE: return "DOUBLE";
        case TYPE_CHAR: return "CHAR";
        case TYPE_BOOL: return "BOOL";
        case TYPE_STRING: return "STRING";
        case TYPE_INT_PTR: return "INT_PTR";
        case TYPE_CHAR_PTR: return "CHAR_PTR";
        case TYPE_DOUBLE_PTR: return "DOUBLE_PTR";
        case TYPE_FLOAT_PTR: return "FLOAT_PTR";
        case TYPE_VOID: return "VOID";
        case TYPE_NULL: return "NULL";
        default: return "UNKNOWN";
    }
}

bool isInteger(const char *str) {
    if (*str == '\0') return false; 

    char *endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0') return false;
    return true;
}


bool isFloat(const char *value) {
    const char *pattern = "^[0-9]+\\.[0-9]+f$";
    
    regex_t regex;
    int ret;
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "Could not compile regex\n");
        return false;
    }
    
    ret = regexec(&regex, value, 0, NULL, 0);
    regfree(&regex);
    return (ret == 0);
}

bool isDouble(const char *value) {
    const char *pattern = "^[0-9]*\\.?[0-9]+([eE][+-]?[0-9]+)?$";
    
    regex_t regex;
    int ret;

    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "Could not compile regex\n");
        return false;
    }

    ret = regexec(&regex, value, 0, NULL, 0);
    regfree(&regex);
    return (ret == 0);
}

bool isBoolean(const char *str) {
    return (strcmp(str, "TRUE") == 0 || strcmp(str, "FALSE") == 0);
}

Type checkType(const char *value) {
    size_t len = strlen(value);

    if (isInteger(value)) {
        return TYPE_INT;
    } else if (isFloat(value)) {
        return TYPE_FLOAT;
    } else if (isDouble(value)) {
        return TYPE_DOUBLE;
    } else if (isBoolean(value)) {
        return TYPE_BOOL;
    }

    if (len == 3 && value[0] == '\'' && value[2] == '\'' && isprint(value[1])) {
        return TYPE_CHAR;
    }

    return TYPE_STRING;
}


int is_numeric(Type t) {
    return t == TYPE_INT || t == TYPE_FLOAT || t == TYPE_DOUBLE;
}

Type get_arithmetic_result_type(Type t1, Type t2) {
    if (t1 == TYPE_DOUBLE || t2 == TYPE_DOUBLE) return TYPE_DOUBLE;
    if (t1 == TYPE_FLOAT || t2 == TYPE_FLOAT) return TYPE_FLOAT;
    if (t1 == TYPE_INT && t2 == TYPE_INT) return TYPE_INT;
    return TYPE_VOID;
}

Type get_comparison_result_type(Type t1, Type t2) {
    if (is_numeric(t1) && is_numeric(t2)) return TYPE_BOOL;
    return TYPE_VOID;
}

Type get_equality_result_type(Type t1, Type t2) {
    if ((t1 == t2) && (is_numeric(t1) || t1 == TYPE_BOOL || t1 == TYPE_CHAR || 
        t1 == TYPE_INT_PTR || t1 == TYPE_CHAR_PTR || t1 == TYPE_DOUBLE_PTR || t1 == TYPE_FLOAT_PTR))
        return TYPE_BOOL;
    return TYPE_VOID;
}
Type check_arithmetic(node* n, Scope* sc){
    if (n == NULL) return TYPE_VOID;

    if (strcmp(n->token, "+") == 0 ||
        strcmp(n->token, "-") == 0 ||
        strcmp(n->token, "*") == 0 ||
        strcmp(n->token, "/") == 0) {
        
        Type leftType = check_arithmetic(n->left, sc);
        Type rightType = check_arithmetic(n->right, sc);
        
        if (is_numeric(leftType) && is_numeric(rightType)) {
            return get_arithmetic_result_type(leftType, rightType);
        } else {
            printf("Error: Invalid types for arithmetic operation '%s'.\n", n->token);
            exit(1);
        }
    }
    else if(strcmp(n->token,"STR_LEN") == 0){
         if(check_expression(n->left, sc) == TYPE_STRING){
            return TYPE_INT;
        }
        else{
            printf("Error: Can't use length operator on non string type\n");
            exit(1);
        }
    } else if(strcmp(n->token, "CALL") == 0){
	Symbol* s = find_symbol(sc, n->left->token);
	    	if(s == NULL){
	    		 printf("Error: Function '%s' is not defined in the current scope.\n", n->token);
	    		 exit(1);
	    	}   
        Type t = s->return_type;
        if(is_numeric(t))
            return t;
    }
    else if(n->left != NULL && strcmp(n->left->token, "ID") == 0){
    	Symbol* s = find_symbol(sc, n->token);
    	if(s == NULL){
    		 printf("Error: Variable '%s' is not defined in the current scope.\n", n->token);
    		 exit(1);
    	}
        Type t = s->type;
        if(is_numeric(t))
            return t;
    }
    Type nodeType = checkType(n->token);
    if (is_numeric(nodeType)) {
        return nodeType;
    } else {
        printf("Error: Unsupported node type for arithmetic operation '%s'.\n", n->token);
        exit(1);
    }
}
Type check_equality(node* n, Scope* sc) {
    if (n == NULL) return TYPE_VOID;

    if (strcmp(n->token, "==") == 0 || strcmp(n->token, "!=") == 0) {
        Type leftType = check_expression(n->left, sc);
        Type rightType = check_expression(n->right, sc);

        if (is_comparable(leftType) && is_comparable(rightType) &&
            (leftType == rightType || 
             (check_ptr(leftType) && check_ptr(rightType) && (leftType == rightType)))) {
            return TYPE_BOOL;
        } else {
            printf("Error: Operands of '%s' must be of comparable types.\n", n->token);
            exit(1);
        }
    }

    Type nodeType = check_expression(n, sc);
    if (is_comparable(nodeType) || check_ptr(nodeType)) {
        return nodeType;
    } else {
        printf("Error: Unsupported node type for equality operation '%s'.\n", n->token);
        exit(1);
    }
}
Type check_expression(node* n, Scope* sc) {
    
    if (n == NULL) return VOID;
    
    if (strcmp(n->token, "+") == 0 || strcmp(n->token, "-") == 0 ||
        strcmp(n->token, "*") == 0 || strcmp(n->token, "/") == 0) {
        return check_arithmetic(n, sc);
    } else if (strcmp(n->token, "&&") == 0 || strcmp(n->token, "||") == 0) {
        return check_logical(n, sc);
    } else if (strcmp(n->token, ">") == 0 || strcmp(n->token, "<") == 0 ||
               strcmp(n->token, ">=") == 0 || strcmp(n->token, "<=") == 0) {
        return check_relational(n, sc);
    } else if(strcmp(n->token, "==") == 0 || strcmp(n->token, "!=") == 0){
        return check_equality(n,sc);
    }else if(strcmp(n->token,"STR_LEN") == 0){
        if(check_expression(n->left, sc) == TYPE_STRING){
            
            return TYPE_INT;
        }
        else{
            printf("Error: Can't use length operator on non string type\n");
            exit(1);
        }
        
    } else if(strcmp(n->token,"!") == 0 && n->right == NULL){
        return check_logical(n->left, sc);
    
     }else if(n->left != NULL && strcmp(n->left->token,"ID")==0){
      
        Symbol* s = find_symbol(sc,n->token);
        if(s == NULL){
            printf("Error: Variable '%s' is not defined.\n", n->token);
            exit(1);
        }
        return s->type;
    } else if(strcmp(n->token, "CALL") == 0){
        Symbol* s = find_symbol(sc,n->left->token);

        if(s == NULL || (s != NULL && s->return_type == TYPE_NULL)){
            printf("Error: Function '%s' is not defined.\n", n->left->token);
            exit(1);
        }
        if (!check_function_definitions(sc, n->left->token)) {
            exit(1);
        }
        int num_args = 0;
        funcArgs argsArray[50];
        extract_arguments(n, argsArray, &num_args, sc);
        if (!check_function_arguments(sc, n->left->token, num_args, argsArray)) {
            exit(1);
        }
        return s->return_type;
    }
    else if(strcmp(n->token, "expr") == 0){
        
        return check_expression(n->left, sc);
    } else if(n->left != NULL && strcmp(n->left->token, "ARRAY_ELEM") == 0) {
        
        Symbol* s = find_symbol(sc, n->token);
        if(s == NULL){
            printf("Error: Variable '%s' is not defined.\n", n->token);
            exit(1);
        }
        if(s->type != TYPE_STRING){
            printf("Can't access array element of a non string identifier\n");
            exit(1);
        }
        if(check_expression(n->left->left, sc) != TYPE_INT){
            printf("Error: Index type must be of type INT.\n");
            exit(1);
        }
        return TYPE_CHAR;       
    }else if(strcmp(n->token, "NULL") == 0){
        return TYPE_NULL;
    }else if(strcmp(n->token, "&") == 0){
        Symbol* s = find_symbol(sc, n->left->token);
        if(!(s != NULL && (is_numeric(s->type) || is_string_elem(n,s, sc) || s->type == TYPE_CHAR))){
            printf("Error: The address-of operator '&' can only be applied to variables of type int, float, double, char, or string element.\n");
            exit(1);
        }
        if(is_string_elem(n,s,sc)){
            return TYPE_CHAR;
        }
        return s->type;
        
    }else {
       
        return checkType(n->token);
    }
}

int is_comparable(Type type) {
    return is_numeric(type) || type == TYPE_CHAR || type == TYPE_BOOL || check_ptr(type);
}

Type check_logical(node* n, Scope *sc) {
    if (n == NULL) return TYPE_VOID;

    if (strcmp(n->token, "&&") == 0 || strcmp(n->token, "||") == 0) {

        Type leftType = check_logical(n->left,sc);
        Type rightType = check_logical(n->right,sc);

        if (leftType == TYPE_BOOL && rightType == TYPE_BOOL) {
            return TYPE_BOOL;
        } else {
            printf("Error: Both operands of '%s' must be of type BOOL.\n", n->token);
            exit(1);
        }
    }
    else if (strcmp(n->token, ">") == 0 || strcmp(n->token, "<") == 0 ||
        strcmp(n->token, ">=") == 0 || strcmp(n->token, "<=") == 0) {
        return check_relational(n, sc);
    }
    else if (strcmp(n->token, "==") == 0 || strcmp(n->token, "!=") == 0) {
        return get_equality_result_type(check_expression(n->left, sc), check_expression(n->right, sc));
    }
    else if(strcmp(n->token,"!") == 0 && n->right == NULL){
        return check_logical(n->left, sc);
    }
    else if(strcmp(n->token, "CALL") == 0){
    	Symbol* s = find_symbol(sc,n->left->token);
        if(s == NULL){
            printf("Error: Function '%s' is not defined.\n", n->token);
            exit(1);
        }
        if(s->return_type == TYPE_BOOL){
        	return TYPE_BOOL;
        }
    }
    else if(n->left != NULL && strcmp(n->left->token, "ID") == 0){
    	Symbol* s = find_symbol(sc,n->token);
        if(s == NULL){
            printf("Error: Variable '%s' is not defined.\n", n->token);
            exit(1);
	}
        if(s->type == TYPE_BOOL){
        	return TYPE_BOOL;
    	}
	}
    else if(strcmp(n->token, "expr") == 0){
        
        return check_logical(n->left, sc);
    }
    Type nodeType = checkType(n->token);
    if (isBoolean(typeToString(nodeType)) || isBoolean(n->token)) {
        return TYPE_BOOL;
    } else {
        printf("Error: Unsupported type for logical operation, expected BOOL and got '%s'.\n", typeToString(check_expression(n, sc)));
        exit(1);
    }
}

Type check_relational(node* n, Scope* sc) {
    if (n == NULL) return TYPE_VOID;

    if (strcmp(n->token, ">") == 0 || strcmp(n->token, "<") == 0 ||
        strcmp(n->token, ">=") == 0 || strcmp(n->token, "<=") == 0) {
        
        Type leftType = check_arithmetic(n->left, sc);
        Type rightType = check_arithmetic(n->right, sc);

        if (is_numeric(leftType) && is_numeric(rightType)) {
            return TYPE_BOOL;  
        } else {
            printf("Error: Both operands of '%s' must be int, float, or double.\n", n->token);
            exit(1);
        }
    }

    Type nodeType = checkType(n->token);
    if (is_numeric(nodeType)) {
        return nodeType;
    } else {
        printf("Error: Unsupported node type for relational operation '%s'.\n", n->token);
        exit(1);
    }
}

int is_string_elem(node* root, Symbol *s, Scope* sc){
    if(root->right == NULL)
        return 0;
    if(!(strcmp(root->right->token, "ARRAY_ELEM") == 0 )){
        return 0;
    }
    //printf("%s, %s\n", typeToString(s->type), typeToString(check_arithmetic(root->right->left, sc)));
    if(s->type == TYPE_STRING && check_arithmetic(root->right->left, sc) == TYPE_INT){
        return 1;
        
    }
    return 0;
}

int check_ptr(Type t){
    if(t == TYPE_INT_PTR || t == TYPE_FLOAT_PTR || t == TYPE_DOUBLE_PTR || t == TYPE_CHAR_PTR)
        return 1;
    return 0;
}
int check_public(node* root){
    
    if(strcmp(root->left->left->token,"PRIVATE") == 0){
        return 0;
    }
    return 1;
}

// part-3 -------------------------------------------------------------------------------------------------------------------------


void handle_function(node* root, func *funcs) {
    node* funcBody = root;
    variable var[100];
    int varCount = 0;
    //funcs[funcs_counter].name = (char *)malloc(strlen(root->left->token) + 1);
    strcpy(funcs[funcs_counter].name, root->left->token);
    funcs[funcs_counter].params_size = count_parameters_size(root);
    add_parameters_var(root, var, &varCount);
    if(strcmp(root->left->right->token, "VOID") == 0){
        funcs[funcs_counter].has_type = false;
    }
    else{
        funcs[funcs_counter].has_type = true;
    }
    funcs_counter++;
    printf("%s:\n", root->left->token);
    while(funcBody->right != NULL && (strcmp(funcBody->token, "func_body") != 0 && strcmp(funcBody->token, "RETURN VOID") != 0)){
        funcBody = funcBody->right;
    }
    printf("\tBeginFunc %d\n", calculate_function_size(funcBody, stringToType(root->left->right->token), var, &varCount));

    int i = 0;
    while (funcBody != NULL && strcmp(funcBody->token, "func_body") == 0) {
        code_generator(funcBody->left, funcs);
        funcBody = funcBody->right;
    }
    if(funcBody != NULL && strcmp(funcBody->token, "return_statement") == 0){
            if(strcmp(funcBody->left->token, "RETURN VOID") == 0){
                    printf("\tRETURN;\n");                              
            }
            else if(strcmp(funcBody->left->token, "RETURN") == 0){
                    printf("\tRETURN %s;\n", check_expression_3ac(funcBody->left->left, funcs));
            }  
    }
  
    printf("\tEndFunc\n");
}

void handle_if_else(node* root, func *funcs) {
    int false_label, resume_label;
    int true_label = new_label();

    if (root->right == NULL) {
        false_label = new_label();
        evaluate_condition(root->left->left, funcs, &false_label, &true_label, 0);
        printf("L%d:\n", true_label);
        
        code_generator(root->left->right->left, funcs);
        resume_label = false_label;
    } else {
        false_label = new_label();
        
        evaluate_condition(root->left->left, funcs, &false_label, &true_label, 0);
        //if statement
        printf("L%d:\n", true_label);
        code_generator(root->left->right->left, funcs);
        resume_label = new_label();
        printf("\tGoto L%d\n", resume_label);
        //else statement
        printf("L%d:\n", false_label);
        code_generator(root->right->left, funcs);
    }

    printf("L%d:\n", resume_label);
}

int calculate_for_statement(node* root,UnassignedVar unassigned_vars[], int* unassigned_count, variable var[], int* varCount, Type type) {
    int total_size = 0;
    //for_init
    node* tempRoot = root->left->left;
    while(tempRoot != NULL){
        total_size += calculate_statement_size(tempRoot, unassigned_vars, unassigned_count, var, varCount, type);
        tempRoot = tempRoot->right;
    }
    total_size += calculate_condition(root->left->right->left);
    total_size += calculate_statement_size(root->right->left, unassigned_vars, unassigned_count, var, varCount, type);
    if(root->left->right != NULL) 
        total_size += calculate_statement_size(mknode("",root->left->right->right, NULL), unassigned_vars, unassigned_count, var, varCount, type);
    return total_size;
}

int calculate_do_while_statement(node* root, UnassignedVar unassigned_vars[], int* unassigned_count, variable var[], int* varCount, Type type) {
    int total_size = 0;
    total_size += calculate_statement_size(root->left, unassigned_vars, unassigned_count, var, varCount, type);
    total_size += calculate_condition(root->right->left);
    return total_size;
    
}
int calculate_while_statement(node* root,UnassignedVar unassigned_vars[], int* unassigned_count, variable var[], int* varCount, Type type) {
    int total_size = 0;
    total_size += calculate_condition(root->left);
    total_size += calculate_statement_size(root->right->left, unassigned_vars, unassigned_count, var, varCount, type);
    return total_size;
}

int calculate_if_else(node* root,UnassignedVar unassigned_vars[], int* unassigned_count, variable var[], int* varCount, Type type) {
    int total_size = 0;
    if (root->right == NULL) {
       
        total_size += calculate_condition(root->left->left);
        total_size += calculate_statement_size(root->left->right->left, unassigned_vars, unassigned_count, var, varCount, type);
    } else {
       
        total_size += calculate_condition(root->left->left);
        total_size += calculate_statement_size(root->left->right->left, unassigned_vars, unassigned_count,var, varCount, type);
        total_size += calculate_statement_size(root->right->left, unassigned_vars, unassigned_count, var, varCount, type);
    }
    return total_size;
}
int calculate_condition(node* condition) {
    int total_size = 0;
    if(strcmp(condition->token, "expr") == 0){
        total_size += calculate_condition(condition->left);
    }
    else if (strcmp(condition->token, "&&") == 0) {
        node* temp_root = condition->left;
        while(temp_root->left != NULL && (strcmp(temp_root->token, "expr") == 0)){
            temp_root = temp_root->left;
        }
        total_size += calculate_condition(condition->left);
        total_size += calculate_condition(condition->right);
        
    } 
    else if (strcmp(condition->token, "||") == 0) {
        node* temp_root = condition->left;
        while(temp_root->left != NULL && (strcmp(temp_root->token, "expr") == 0)){
            temp_root = temp_root->left;
        }
        total_size += calculate_condition(condition->left);
        total_size += calculate_condition(condition->right);
        
    } 
    else if (strcmp(condition->token, "==") == 0 || strcmp(condition->token, "!=") == 0 ||
             strcmp(condition->token, ">") == 0 || strcmp(condition->token, "<") == 0 ||
             strcmp(condition->token, ">=") == 0 || strcmp(condition->token, "<=") == 0) {
        // Comparison operation
        total_size += calculate_condition(condition->left);
        total_size += calculate_condition(condition->right);
        total_size += 4; //bool
    } 
    
    return total_size;
}

char* evaluate_condition(node* condition, func *funcs, int* false_label, int* true_label, int calls_counter) {

    char* temp_var = NULL;
    if(strcmp(condition->token, "expr") == 0){
        char a = evaluate_condition(condition->left, funcs, false_label, true_label, calls_counter);
        return a;
    }
    else if (strcmp(condition->token, "&&") == 0) {
        node* temp_root = condition->left;
        while(temp_root->left != NULL && (strcmp(temp_root->token, "expr") == 0)){
            temp_root = temp_root->left;
        }
        int temp_label = -1;
        if(temp_root != NULL && strcmp(temp_root->token,"||") == 0){
            
            temp_label = *false_label;
            //*true_label = *false_label;
            *false_label = new_label();
        }
        char* left = evaluate_condition(condition->left, funcs, false_label, true_label, calls_counter + 1);
        if(temp_label != -1){
            printf("L%d:", *true_label);
            *true_label = temp_label;
        }
        if(temp_label == -1 && left){
            printf("\tifz %s Goto L%d\n", left, *false_label);
        }
        char* right =  evaluate_condition(condition->right, funcs, false_label, true_label, calls_counter + 1);
        if(right){
            printf("\tifz %s Goto L%d\n", right, *false_label);
            
                printf("\tGoto L%d\n", *true_label);
        
        }
    } 
    else if (strcmp(condition->token, "||") == 0) {
        node* temp_root = condition->left;
        while(temp_root->left != NULL && (strcmp(temp_root->token, "expr") == 0)){
            temp_root = temp_root->left;
        }
        int temp_label = -1;
        if(temp_root != NULL && strcmp(temp_root->token,"&&") == 0){
            temp_label = *true_label;
            *true_label = *false_label;
            *false_label = temp_label;
        }
        char* left = evaluate_condition(condition->left, funcs, false_label , true_label, calls_counter + 1);
        if(temp_label != -1){
            printf("L%d:", *false_label);
            *false_label = new_label();
        }
        if(temp_label == -1 && left){
            printf("\tif %s Goto L%d\n", left, *true_label);
        }
        
        char* right = evaluate_condition(condition->right, funcs, false_label, true_label, calls_counter + 1);
        if(right){
            printf("\tif %s Goto L%d\n", right, *true_label);
            
                printf("\tGoto L%d\n", *false_label);
            
        }
        
    } 
    else if (strcmp(condition->token, "==") == 0 || strcmp(condition->token, "!=") == 0 ||
             strcmp(condition->token, ">") == 0 || strcmp(condition->token, "<") == 0 ||
             strcmp(condition->token, ">=") == 0 || strcmp(condition->token, "<=") == 0) {
        // Comparison operation
        char* left = evaluate_condition(condition->left, funcs, false_label, true_label, calls_counter + 1);
        char* right = evaluate_condition(condition->right, funcs, false_label, true_label, calls_counter + 1);
        temp_var = new_temp_var();
        printf("\t%s = %s %s %s\n", temp_var, left, condition->token, right);

        // Only print the if statement and Goto if it's not inside an `&&` or `||` context
        if (calls_counter == 0) {
            printf("\tif %s Goto L%d\n", temp_var, *true_label);
            printf("\tGoto L%d\n", *false_label);
        }
    } 
    else {
        // If it's a single condition, return the generated code
        temp_var = code_generator(condition, funcs);
        // Only print the if statement and Goto if it's not inside an `&&` or `||` context
        if (calls_counter == 0) {
            printf("\tif %s Goto L%d\n", temp_var, *true_label);
            printf("\tGoto L%d\n", *false_label);
        }
    }

    return temp_var;
}

void handle_do_while_statement(node* root, func *funcs) {
    int loop_label = new_label();
    int  true_label= new_label();
    int false_label = new_label();
    
    printf("L%d:\n", loop_label);
    code_generator(root->left, funcs);
    evaluate_condition_do_while(root->right->left, funcs, &false_label, &true_label, loop_label, 0);
    
}
/* void calculate_do_while_statement(node* root, func *funcs) {

    code_generator(root->left, funcs);
    evaluate_condition_do_while(root->right->left, funcs, &false_label, &true_label, loop_label, 0);
    
} */

char* evaluate_condition_do_while(node* condition, func *funcs, int* false_label, int* true_label, int loop_label, int calls_counter) {

    char* temp_var = NULL;
    if(strcmp(condition->token, "expr") == 0){
        char a = evaluate_condition_do_while(condition->left, funcs, false_label, true_label,loop_label, calls_counter);
        return a;
    }
    else if (strcmp(condition->token, "&&") == 0) {
        node* temp_root = condition->left;
        while(temp_root->left != NULL && (strcmp(temp_root->token, "expr") == 0)){
            temp_root = temp_root->left;
        }
        int temp_label = -1;
        if(temp_root != NULL && strcmp(temp_root->token,"||") == 0){
            temp_label = 1;
            
        }
        else if(temp_root != NULL && strcmp(temp_root->token,"&&") == 0){
            temp_label = 1;
        }
        else{
            if(calls_counter == 0){
                int t_label = *true_label;
                *true_label = loop_label;
                *false_label = t_label;
            }
        }
        char* left = evaluate_condition_do_while(condition->left, funcs, false_label, true_label,loop_label, calls_counter + 1);
        if(temp_label != -1){
            printf("L%d:", *true_label);
            *true_label = temp_label;
        }
        if(temp_label == -1 && left){
            printf("\tifz %s Goto L%d\n", left, *false_label);
        }
        char* right =  evaluate_condition_do_while(condition->right, funcs, false_label, &loop_label,loop_label, calls_counter + 1);
        if(right){
            printf("\tifz %s Goto L%d\n", right, *false_label);
            
                printf("\tGoto L%d\n", *true_label);
        
        }
        if(calls_counter == 0){
            printf("L%d:\n", *false_label);
        }
    } 
    else if (strcmp(condition->token, "||") == 0) {
        node* temp_root = condition->left;
        while(temp_root->left != NULL && (strcmp(temp_root->token, "expr") == 0)){
            temp_root = temp_root->left;
        }
        int temp_label = -1;
        if(temp_root != NULL && strcmp(temp_root->token,"&&") == 0){
            
            temp_label = 1;
        }
        else if(temp_root != NULL && strcmp(temp_root->token,"||") == 0){
  
            temp_label = 1;
        }
        else{
            if(calls_counter == 0){
                int t_label = *true_label;
                *true_label = loop_label;
                *false_label = t_label;
            }
        }
        char* left = evaluate_condition_do_while(condition->left, funcs, true_label , &loop_label,loop_label, calls_counter + 1);
        if(temp_label != -1){
            printf("L%d:", *true_label);
        }
        if(temp_label == -1 && left){
            printf("\tif %s Goto L%d\n", left, *true_label);
        }
        
        char* right = evaluate_condition_do_while(condition->right, funcs, false_label, &loop_label,loop_label, calls_counter + 1);
        if(right){
            printf("\tif %s Goto L%d\n", right, *true_label);
            
                printf("\tGoto L%d\n", *false_label);
            
        }
        if(calls_counter == 0){
            printf("L%d:\n", *false_label);
        }
        
    } 
    else if (strcmp(condition->token, "==") == 0 || strcmp(condition->token, "!=") == 0 ||
             strcmp(condition->token, ">") == 0 || strcmp(condition->token, "<") == 0 ||
             strcmp(condition->token, ">=") == 0 || strcmp(condition->token, "<=") == 0) {
        // Comparison operation
        char* left = evaluate_condition_do_while(condition->left, funcs, false_label, true_label,loop_label, calls_counter+1);
        char* right = evaluate_condition_do_while(condition->right, funcs, false_label, true_label,loop_label, calls_counter+1);
        temp_var = new_temp_var();
        printf("\t%s = %s %s %s\n", temp_var, left, condition->token, right);

        // Only print the if statement and Goto if it's not inside an `&&` or `||` context
        if (calls_counter == 0) {
            printf("\tif %s Goto L%d\n", temp_var, loop_label);
            printf("\tGoto L%d\n", *true_label);
            printf("L%d:\n", *true_label);
        }
    } 
    else {
        // If it's a single condition, return the generated code
        temp_var = code_generator(condition, funcs);
        // Only print the if statement and Goto if it's not inside an `&&` or `||` context
        if (calls_counter == 0) {
            printf("\tif %s Goto L%d\n", temp_var, loop_label);
            printf("\tGoto L%d\n", *true_label);
            printf("L%d:\n", *true_label);
        }
    }

    return temp_var;
}

char* code_generator(node* root, func *funcs) {
    if (root == NULL) return NULL;

    if (strcmp(root->token, "DECLARE") == 0) {
        node* varNode = root->right;
        while (varNode != NULL) {
            if (strcmp(varNode->token, "VAR") == 0) {
                // Declare the variable
                
            } else if (strcmp(varNode->token, "ASS") == 0) {
                
                char* left = varNode->left->token;
                char* right;
                if(strcmp(varNode->right->token, "&") == 0){
                    
                    right = varNode->right->left->token;
                    printf("\t%s = &%s\n", left, right);
                }
                else{
                    right = check_expression_3ac(varNode->right, funcs);
                    printf("\t%s = %s\n", left, right);
                }
            } else if (strcmp(varNode->token, "SEQUENCE") == 0) {
                code_generator(varNode->left, funcs);
            }

            varNode = varNode->right;
        }
        if (strcmp(root->left->token, typeToString(TYPE_STRING)) == 0){
            
            varNode = root;
            while(varNode->right != NULL){
                varNode = varNode->right;
                if(strcmp(varNode->token, "STRING_ASSIGNMENT") == 0){
                    printf("\t%s = %s\n", varNode->left->left->token, check_expression_3ac(varNode->left->right,funcs));
                }
                return NULL;
            }
        }
    } else if (strcmp(root->token, "CALL") == 0) {
        node* tempRoot = root->right;
        while(tempRoot != NULL){
            char* temp = check_expression_3ac(tempRoot->left, funcs);
            printf("\tPushParam %s\n", temp);
            tempRoot = tempRoot->right;
        }
        
        int i = 0;
        while (i < funcs_counter && strcmp(funcs[i].name, root->left->token) != 0) {
            printf("%s\n", funcs[i].name);
            i++;
        }
        if(funcs[i].has_type){
            char* temp_var = new_temp_var();
            printf("\t%s = LCALL %s\n", temp_var, root->left->token);
            printf("\tPopParams %d\n", funcs[i].params_size);
            return temp_var;
        }
        else{
            printf("\tLCALL %s\n", root->left->token);
            printf("\tPopParams %d\n", funcs[i].params_size);
        }
    } else if (strcmp(root->token, "WHILE") == 0) {
        handle_while_statement(root, funcs);
    }else if (strcmp(root->token, "do-statement") == 0) {
        handle_do_while_statement(root, funcs);
    } else if (strcmp(root->token, "FOR") == 0) {
        handle_for_statement(root, funcs);
    } else if (strcmp(root->token, "if_expr") == 0) {
        handle_if_else(root, funcs);
    } else if (strcmp(root->token, "ASS") == 0) {
        char* left = root->left->token;
        char* right;
            if(strcmp(root->right->token, "&") == 0){
                right = root->right->left->token;
                printf("\t%s = &%s\n", left, right);
            }
            else{
                right = check_expression_3ac(root->right, funcs);
                printf("\t%s = %s\n", left, right);
            }
        
        
        //char* temp_var = new_temp_var();
        //printf("\t%s = %s\n", temp_var, right);
        
        return left;
     } else if(strcmp(root->token, "STRING_ASSIGNMENT") == 0) {
        while(root != NULL){
            if(strcmp(root->token, "STRING_ASSIGNMENT") == 0){
                printf("\t%s = %s\n", root->left->left->token, check_expression_3ac(root->left->right,funcs));
            }
            root = root->right;
        }
        return NULL;
     }else if(strcmp(root->token, "STRING_ASSIGN") == 0 || strcmp(root->token, "ASSIGN_ARRAY_ELEM") == 0) {
        /*arr[3] <- 'a';
        t1 = index(3) * 1;
        t2 = ID(arr) + t1
        t3 = *t2
        t3 = 'a'
        */
        char* temp_var = new_temp_var();
        char* index = check_expression_3ac(root->left->left->left, funcs);
        printf("\t%s = %s * 1\n", temp_var, index);
        char* temp_var2 = new_temp_var();
        printf("\t%s = %s + %s\n", temp_var2, root->left->token, temp_var);
        char* temp_var3 = new_temp_var();
        printf("\t%s = *%s\n", temp_var3, temp_var2);
        printf("\t%s = %s\n", temp_var3, check_expression_3ac(root->right,funcs));
        return NULL;
    }else if(strcmp(root->token, "BRACKETS") == 0){ 
        return code_generator(root->left, funcs);
    } else if(strcmp(root->token, "statement_list") == 0){
        node* statement_list = root;
        do{
            code_generator(statement_list->left,funcs);
            statement_list = statement_list->right;
        }
        while(statement_list != NULL);
    } else if(strcmp(root->token, "return_statement") == 0){
            if(strcmp(root->left->token, "RETURN VOID") == 0){
                    printf("\tRETURN;\n");                              
            }
            else if(strcmp(root->left->token, "RETURN") == 0){
                    printf("\tRETURN %s;\n", check_expression_3ac(root->left->left, funcs));
            }
             
    } else {
        if (strcmp(root->token, "") != 0) {
            return root->token;
        } else {
            return code_generator(root->left, funcs);
        }
    }

    return NULL;
}
void remove_id(char unassigned_ids[MAX_UNASSIGNED][50], int* unassigned_count, const char* id) {
    for (int i = 0; i < *unassigned_count; i++) {
        if (strcmp(unassigned_ids[i], id) == 0) {
            for (int j = i; j < *unassigned_count - 1; j++) {
                strcpy(unassigned_ids[j], unassigned_ids[j + 1]);
            }
            (*unassigned_count)--;
            break;
        }
    }
}
void add_unassigned_var(UnassignedVar unassigned[], int* count, const char* id, int size) {
    unassigned[*count].id = strdup(id);
    unassigned[*count].size = size;
    (*count)++;
}

int remove_unassigned_var(UnassignedVar unassigned[], int* count, const char* id, int* total_size) {
    for (int i = 0; i < *count; i++) {
        if (strcmp(unassigned[i].id, id) == 0) {
            
            *total_size += unassigned[i].size;
            int size = unassigned[i].size;
            free(unassigned[i].id);
            for (int j = i; j < *count - 1; j++) {
                unassigned[j] = unassigned[j + 1];
            }
            (*count)--;
            return size;
        }
    }
    return 0;
}

void add_unassigned_str(UnassignedVar unassigned[], int* count, const char* id, int* total_size, int size) {
    int flag = 0;
    for (int i = 0; i < *count; i++) {
        if (strcmp(unassigned[i].id, id) == 0) {
            *total_size -= unassigned[i].size;
            int size = unassigned[i].size;
            flag = 1;
            break;
        }
    }
    unassigned[*count].id = strdup(id);
    unassigned[*count].size = size;
    *total_size += size;
    if(flag == 0)
        (*count)++;
}
void add_var(variable var[], int* count, const char* id, Type type){
    var[*count].id = strdup(id);
    var[*count].type = type;
    (*count)++;
}
int extract_type(variable var[], int* count, const char* id){
    for (int i = 0; i < *count; i++) {
        if (strcmp(var[i].id, id) == 0) {
            if(var[i].type == TYPE_STRING)
                return -1;
            return get_data_type_size(var[i].type);
        }
    }
    return 0;
}

int calculate_statement_size(node* funcBody, UnassignedVar unassigned_vars[], int* unassigned_count, variable var[], int* varCount, Type type){
    int total_size = 0;
    if (strcmp(funcBody->token, "DECLARE") == 0) {
            Type t = stringToType(funcBody->left->token);
            int size = get_data_type_size(t);
            node* varNode = funcBody->right;
            while (varNode != NULL) {
                if (strcmp(varNode->token, "VAR") == 0) {
                    add_var(var, varCount, varNode->left->token, t);
                    add_unassigned_var(unassigned_vars, unassigned_count, varNode->left->token, size);
                } else if (strcmp(varNode->token, "ASS") == 0) {
                    total_size += size;
                    total_size += calculate_expression_size(varNode->right, size);
                    add_var(var, varCount, varNode->left->token, t);
                } else if (strcmp(varNode->token, "SEQUENCE") == 0) {
                    if(strcmp(varNode->left->token, "ASS") == 0){
                        add_var(var, varCount, varNode->left->left->token, t);
                        add_unassigned_var(unassigned_vars, unassigned_count, varNode->left->left->token, size);
                        total_size += calculate_statement_size(varNode, unassigned_vars, unassigned_count, var , varCount, type);
                    }
                }
                varNode = varNode->right;
            }
            
            if (strcmp(funcBody->left->token, typeToString(TYPE_STRING)) == 0){
            varNode = funcBody;
            while(varNode->right != NULL){
                varNode = varNode->right;
                add_var(var, varCount, varNode->left->token, TYPE_STRING);
                if(strcmp(varNode->token, "STRING_ASSIGNMENT") == 0){
                    add_var(var, varCount, varNode->left->left->token, TYPE_STRING);
                    add_unassigned_str(unassigned_vars, unassigned_count,  varNode->left->left->token, &total_size, strlen(varNode->left->right->token) - 2);
                }
                else if(strcmp(varNode->token, "STRING_ASSIGN") == 0){
                    add_var(var, varCount, varNode->left->token, TYPE_STRING);
                }
            }
        }
        }
        else if (strcmp(funcBody->token, "WHILE") == 0) {
            total_size += calculate_while_statement(funcBody, unassigned_vars, unassigned_count, var, varCount, type);
        } else if (strcmp(funcBody->token, "do-statement") == 0) {
            total_size += calculate_do_while_statement(funcBody, unassigned_vars, unassigned_count, var, varCount, type);
        }
        else if (strcmp(funcBody->token, "FOR") == 0) {
            total_size += calculate_for_statement(funcBody, unassigned_vars, unassigned_count, var, varCount, type);
        }else if (strcmp(funcBody->token, "if_expr") == 0) {
            total_size += calculate_if_else(funcBody, unassigned_vars, unassigned_count, var, varCount, type);
        } else if (strcmp(funcBody->left->token, "ASS") == 0) {
            
            int size = extract_type(var, varCount, funcBody->left->left->token);
            if(size == -1){
                char* val = funcBody->left->right->token;
                add_unassigned_str(unassigned_vars, unassigned_count,  funcBody->left->left->token, &total_size, strlen(val) - 2);
            }
            else{
                remove_unassigned_var(unassigned_vars, unassigned_count, funcBody->left->left->token, &total_size);
                total_size += calculate_expression_size(funcBody->left->right, size); 
            }
        } 
        else if (strcmp(funcBody->token, "STRING_ASSIGN") == 0 || strcmp(funcBody->token, "ASSIGN_ARRAY_ELEM") == 0) {
            /*arr[3] <- 'a';
            t1 = index(3) * 1;
            t2 = ID(arr) + t1
            t3 = *t2
            t3 = 'a'
            */
        total_size += 4;//int label
        total_size += calculate_expression_size(funcBody->left, 4);
        total_size += 4;//int label
        total_size += 1;//char label
        
        } 
        else if(strcmp(funcBody->token, "return_statement") == 0){
            
            if(strcmp(funcBody->left->token, "RETURN") == 0){
                
                total_size += calculate_expression_size(funcBody->left->left, get_data_type_size(type));
            }
        }
        else if (strcmp(funcBody->token, "BRACKETS") == 0 || strcmp(funcBody->left->token, "statement_list") == 0) {
            total_size += calculate_statement_size(funcBody->left, unassigned_vars, unassigned_count, var, varCount, type);
        } else if(strcmp(funcBody->token, "statement_list") == 0){
        node* statement_list = funcBody;
        do{
            total_size += calculate_statement_size(statement_list->left, unassigned_vars, unassigned_count, var, varCount, type);
            statement_list = statement_list->right;
        }
        while(statement_list != NULL);
        } 
        return total_size;
}

int calculate_function_size(node* root, Type type, variable var[], int* varCount) {
    //printf("begin calculate %s:\n", root->right->token);
    int total_size = 0;
    int unassigned_count = 0;
    UnassignedVar unassigned_vars[100]; // Array to store unassigned variables
    
    node* funcBody = root;
    while (funcBody != NULL && strcmp(funcBody->token, "func_body") == 0) {
        total_size += calculate_statement_size(funcBody->left, unassigned_vars,  &unassigned_count, var, varCount, type);
        funcBody = funcBody->right;
    }

    if(funcBody != NULL && strcmp(funcBody->token, "return_statement") == 0){
        if(strcmp(funcBody->left->token, "RETURN") == 0){
            total_size += calculate_expression_size(funcBody->left->left, get_data_type_size(type));
        }  
    }

    return total_size;
}


char* new_temp_var() {
    char* temp = (char*)malloc(10);
    sprintf(temp, "t%d", temp_counter++);
    return temp;
}

int new_label() {
    return label_counter++;
}

void parse_program(node* treeRoot,func *funcs) {
    if (treeRoot == NULL) return;
        node* root = treeRoot->left;
        
        if (strcmp(root->token, "FUNC") == 0) {
                handle_function(root, funcs);
        }
    parse_program(treeRoot->right, funcs);
}


void handle_while_statement(node* root, func *funcs) {
    int loop_label = new_label();
    int true_label = new_label();
    int false_label = new_label();
    printf("L%d:\n", loop_label);
    evaluate_condition(root->left, funcs, &false_label, &true_label, 0);
    printf("L%d:\n", true_label);
    code_generator(root->right->left, funcs);
    printf("Goto L%d\n", loop_label);
    printf("L%d:\n", false_label);
    
}

void handle_for_statement(node* root, func *funcs) {

    node* tempRoot = root->left->left;
    while(tempRoot != NULL){
        code_generator(tempRoot->left, funcs);
        tempRoot = tempRoot->right;
    }
    int loop_label = new_label();
    int true_label = new_label();
    int false_label = new_label();
    printf("L%d:\n", loop_label);
    evaluate_condition(root->left->right->left, funcs, &false_label, &true_label, 0);
    printf("L%d:\n", true_label);
    code_generator(root->right->left, funcs);
    if(root->left->right != NULL)
        code_generator(root->left->right->right,funcs);
    printf("Goto L%d\n", loop_label);
    printf("L%d:\n", false_label);
}


int get_data_type_size(Type data_type) {
    if (data_type == TYPE_INT) {
        return 4;
    } else if (data_type ==  TYPE_DOUBLE) {
        return 8;
    } else if (data_type ==  TYPE_CHAR) {
        return 1;
    } else if (data_type ==  TYPE_FLOAT) {
        return 4;
    } else if (data_type ==  TYPE_BOOL) {
        return 1;
    } else
        return 4;
    return 0;
}
char* check_expression_3ac(node* n, func* funcs) {
    if (n == NULL) return NULL;

    char* left_3ac = NULL;
    char* right_3ac = NULL;
    char* result;

    if (strcmp(n->token, "+") == 0 || strcmp(n->token, "-") == 0 ||
        strcmp(n->token, "*") == 0 || strcmp(n->token, "/") == 0) {
        result = new_temp_var();
        left_3ac = check_expression_3ac(n->left, funcs);
        right_3ac = check_expression_3ac(n->right, funcs);
        printf("\t%s = %s %s %s\n", result, left_3ac, n->token, right_3ac);
    } else if (strcmp(n->token, "&&") == 0 || strcmp(n->token, "||") == 0) {
        result = new_temp_var();
        left_3ac = check_expression_3ac(n->left, funcs);
        right_3ac = check_expression_3ac(n->right, funcs);
        printf("\t%s = %s %s %s\n", result, left_3ac, n->token, right_3ac);
    } else if (strcmp(n->token, ">") == 0 || strcmp(n->token, "<") == 0 ||
               strcmp(n->token, ">=") == 0 || strcmp(n->token, "<=") == 0) {
        result = new_temp_var();
        left_3ac = check_expression_3ac(n->left, funcs);
        right_3ac = check_expression_3ac(n->right, funcs);
        printf("\t%s = %s %s %s\n", result, left_3ac, n->token, right_3ac);
    } else if (strcmp(n->token, "==") == 0 || strcmp(n->token, "!=") == 0) {
        result = new_temp_var();
        left_3ac = check_expression_3ac(n->left, funcs);
        right_3ac = check_expression_3ac(n->right, funcs);
        printf("\t%s = %s %s %s\n", result, left_3ac, n->token, right_3ac);
    } else if (strcmp(n->token, "STR_LEN") == 0) {
        result = new_temp_var();
        left_3ac = check_expression_3ac(n->left, funcs);
        printf("\t%s = strlen(%s)\n", result, left_3ac);
    } else if (strcmp(n->token, "!") == 0 && n->right == NULL) {
        result = new_temp_var();
        left_3ac = check_expression_3ac(n->left, funcs);
        printf("\t%s = !%s\n", result, left_3ac);
    } else if (strcmp(n->token, "CALL") == 0) {

        node* tempRoot = n->right;
        while(tempRoot != NULL){
            char* temp = check_expression_3ac(tempRoot->left, funcs);
            printf("\tPushParam %s\n", temp);
            tempRoot = tempRoot->right;
        }
        
        int i = 0;
        while (i < funcs_counter && strcmp(funcs[i].name, n->left->token) != 0) {
            printf("%s\n", funcs[i].name);
            i++;
        }
        if(funcs[i].has_type){
            char* temp_var = new_temp_var();
            printf("\t%s = LCALL %s\n", temp_var, n->left->token);
            printf("\tPopParams %d\n", funcs[i].params_size);
            return temp_var;
        }
        else{
            printf("\tLCALL %s\n", n->left->token);
            printf("\tPopParams %d\n", funcs[i].params_size);
        }
    } else if (strcmp(n->token, "&") == 0) {
        result = new_temp_var();
        printf("\t%s = &%s\n", result, n->left->token);
    } else if (strcmp(n->token, "expr") == 0) {
        return check_expression_3ac(n->left, funcs);
    } else {
        return n->token;
    }

    return result;
}

int calculate_expression_size(node* n, int size) {
    if (n == NULL) return NULL;

    int total_size = 0;
    if (strcmp(n->token, "+") == 0 || strcmp(n->token, "-") == 0 ||
        strcmp(n->token, "*") == 0 || strcmp(n->token, "/") == 0) {
        total_size += size + calculate_expression_size(n->left, size) + calculate_expression_size(n->right,size);
    } else if (strcmp(n->token, "&&") == 0 || strcmp(n->token, "||") == 0) {
        total_size += size + calculate_expression_size(n->left, size) + calculate_expression_size(n->right,size);
    } else if (strcmp(n->token, ">") == 0 || strcmp(n->token, "<") == 0 ||
               strcmp(n->token, ">=") == 0 || strcmp(n->token, "<=") == 0) {
        total_size += size + calculate_expression_size(n->left, size) + calculate_expression_size(n->right,size);
    } else if (strcmp(n->token, "==") == 0 || strcmp(n->token, "!=") == 0) {
        total_size += size + calculate_expression_size(n->left, size) + calculate_expression_size(n->right,size);
    } else if (strcmp(n->token, "STR_LEN") == 0) {
        total_size += 4 + calculate_expression_size(n->left, size) + calculate_expression_size(n->right,size);
    } else if (strcmp(n->token, "!") == 0 && n->right == NULL) {
        total_size += size + calculate_expression_size(n->left, size);
    } else if (strcmp(n->token, "CALL") == 0) {
        node* tempRoot = n->right;
        while(tempRoot != NULL){
            total_size += size + calculate_expression_size(n->left, size);
            tempRoot = tempRoot->right;
        }
    } else if (strcmp(n->token, "&") == 0) {
        total_size += size;
    } else if (strcmp(n->token, "expr") == 0) {
        total_size += calculate_expression_size(n->left, size);
    }

    return total_size;
}