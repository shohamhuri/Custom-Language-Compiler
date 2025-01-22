# Compiler Project

## Introduction
This project involves the design and implementation of a compiler for a procedural programming language. The compiler includes multiple phases such as lexical analysis, syntax parsing, semantic analysis, and intermediate code generation (3AC). Each phase is implemented according to well-defined specifications to ensure correctness and efficiency.

## Features
### 1. Scanner and Parser
- **Lexical Analysis**: Tokenizes the input code using `lex`, identifying keywords, operators, literals, and identifiers.
- **Syntax Parsing**: Uses `yacc` to parse the tokens into an Abstract Syntax Tree (AST) based on the language grammar.
- **Error Handling**: Detects syntax errors and provides detailed messages specifying the error type and location.

### 2. Semantic Analysis
- Implements a symbol table to enforce semantic rules, including:
  - Single `main()` function, public and static.
  - No duplicate function or variable names within the same scope.
  - Variables and functions must be declared before usage.
  - Function calls must match defined argument types and counts.
  - Proper type checking for assignments, operations, and expressions.
- Provides detailed error messages for semantic violations.

### 3. Intermediate Code Generation (3AC)
- Generates three-address code for the input program.
- Handles logical expressions using short-circuit evaluation.
- Supports conditional statements, loops, and function calls.
- Outputs formatted 3AC with labels for flow control and indentation for readability.

## Language Features
- **Data Types**: Supports `int`, `double`, `float`, `char`, `string`, and pointers.
- **Control Structures**: Includes `if`, `else`, `while`, `for`, and `do-while` statements.
- **Functions**: Public and private, static and non-static, with support for nested functions.
- **Operators**: Arithmetic, logical, relational, and pointer-specific operations.

## File Structure
- **`project.l`**: Contains the `lex` rules for tokenizing the input.
- **`project.y`**: Contains the `yacc` grammar rules for parsing and generating the AST.
- **Documentation**:
  - `Language.pdf`: Detailed description of the language syntax and semantics.
  - `project-part1.pdf`: Specifications for the scanner and parser.
  - `project-part2.pdf`: Semantic analysis requirements and rules.
  - `project-part3.pdf`: Intermediate code generation (3AC) specifications.

## Installation
### Prerequisites
- GCC or any C compiler.
- `flex` and `bison` installed on your system.

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/username/compiler-project.git
   cd compiler-project
   ```
2. Compile the scanner and parser:
   ```bash
   flex project.l
   bison -d project.y
   gcc -o compiler lex.yy.c project.tab.c -lfl
   ```
3. Run the compiler with an input file:
   ```bash
   ./compiler < input_code.txt > output.ast
   ```

## Usage
- Provide a source code file (`.txt`) written in the defined language.
- The output includes the Abstract Syntax Tree (AST) and, if enabled, the three-address code (3AC).
- Errors (syntax or semantic) will be displayed with detailed messages.

## Example
### Input Code
```c
public int foo(args>> int: x, y, z; float: f): static {
    if (x > y) {
        x <- x + y;
    } else {
        y <- x + y + z;
        z <- y * 2;
        f <- z;
    }
    return z;
}
```

### Output (3AC)
```
foo:
 BeginFunc 24
 t0 = x + y
 x = t0
 if x > y Goto L1
 goto L2
 L1: t1 = 10
 b = t1
 Goto L3
 L2: t2 = 19
 b = t2
 L3: t3 = b + x
 Return t3
 EndFunc
```

## Future Enhancements
- Add optimization passes for 3AC.
- Extend the language to support arrays and classes.
- Generate machine code using tools like LLVM.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
