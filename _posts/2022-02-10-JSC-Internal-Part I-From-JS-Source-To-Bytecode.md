---
layout: post
title: JSC Internal Part I - From JS Source To Bytecode
category: [browser]
tags: [browser]
---

I've researched about jsc for a long time by analyzing bugs, but all of them are just scattered learning without systematic analysis. To become more professional, i decide to audit the jsc code from the very begining to the end including parser, lint, dfg.

These should be series of posts and this is the first post which covers how to compile js souce code to bytecode. Thanks very much for those who are willing to share the research publicly, especially [Zon8 Research](https://zon8.re/) team, it helps me a lot.

Before getting into this paper, i strongly suggest that you should read official article [A New Bytecode Format for JavaScriptCore](https://webkit.org/blog/9329/a-new-bytecode-format-for-javascriptcore/) fist which  explains the bytecode in very detail. In this post, i'll take you as knowing the basic knowledge about bytecode as default.

## Workflow

Let me give you a overall workflow about compiling js to bytecode. In general, the whole process can be concluded as four parts:

1. Initialize the runtime.
2. Parse to AST
3. Generate unlinked bytecode
4. Generate linked bytecode
5. Ready to execute bytecode

The jsc tries to initialize the runtime at first, it initializes `WTF` framework and sets the runtime flag according to command line arguments, it also creates the `VM` object for the process, and most importantly, generates `globalObject` object, which is responsible for initializing the required builtins and other runtime setup activities. At last it will read js code to memory form file.

After initializing the runtime, it will try to lex and parse the js source to AST. It first initializes a `parser` object, and then build a `ASTBuilder` to store the `AST`. The `parser`  loops to lex the souce code,  parse it to `statement`(` ast node`), append the `statement ` to `ASTBuilder`, and go back to lex. In the end, it builds a `AST` tree.

When the `AST` tree is generated, jsc will try to generate `unlinked` bytecode(`unlinkedCodeBlock`) with the `AST` tree. At first, it will build a `BytecodeGenerator` object which is responsible for traverse every `AST` node and generate corresponding bytecode. The `BytecodeGenerator` will first emit bytecode for the program prologue, and then traverse every `ast` node and generate corresponding bytecode. At last it will call `finalize` function to finish the generation of the `unlinkedCodeBlock` object.

After that, jsc will try to link the `unlinked` bytecode and generate the `linked` bytecode. It will traverse every `unlinked` bytecode and link it to code block, it will also build the `Metadata table` for the bytecode in this process.

When finished the generation of `linked` bytecode, it will set the code object to entry point, and set up the program frame to execute, now jsc can goes into the `LLInt` to interpreter the `bytecode`.

In the next chapters, i'll dive into the source code to explain the upper processes. For brievity, i'll truncate the code as much as possible, and only leave the key code.

I read the source code with debugging the `jsc` in gdb, the source code is shown as follow:

```js
// filename: demo.js

let x = 10;
let y = 20;
let z = x + y;
```

## Initialize the runtime

Now we go into the first part to see how jsc initialize the runtime. 

The entry point is `jscmain` function which is called by `main`. In the main function, it initialize some environments, and then initialize the `Web Template Framework (WTF)` which is a set of commonly used functions from the Webkit codebase by calling the `WTF::initialize()` function. 

```c++
// jsc.cpp: 2956
int main(int argc, char** argv)
{
		...
    // Need to initialize WTF before we start any threads. Cannot initialize JSC
    // yet, since that would do somethings that we'd like to defer until after we
    // have a chance to parse options.
    WTF::initialize();
#if PLATFORM(COCOA)
    WTF::disableForwardingVPrintfStdErrToOSLog();
#endif

    ...
        res = jscmain(argc, argv);
    ...
}
```

In the `jscmain` function, it will continue initializing things. In `main` function, it initialized part of `WTF` framework,  now it calls `WTF::initializeMainThread` function to initialize the `WTF` in more detail. After that, it call `mainCommandLine.construct` function  to parse the `command line`. As the comments shows, command options can affect VM creation, for example,  `--useConcurrentJIT=false` will disable concurrent JIT compile, so it need parse the `command line` first. Next it initializes the `JSC` object, and then call `runJSC` function. Note that the `runWithOptions` is passed as the forth parameter for the `runJSC` function.

```c++
// jsc.cpp: 3699
int jscmain(int argc, char** argv)
{
    // Need to override and enable restricted options before we start parsing options below.
    Config::enableRestrictedOptions();

    WTF::initializeMainThread();

    // Note that the options parsing can affect VM creation, and thus
    // comes first.
    mainCommandLine.construct(argc, argv);

    ...

    JSC::initialize();
  	...

    int result = runJSC(
        mainCommandLine.get(), false,
        [&] (VM& vm, GlobalObject* globalObject, bool& success) {
            UNUSED_PARAM(vm);
#if PLATFORM(COCOA)
            vm.setOnEachMicrotaskTick(WTFMove(onEachMicrotaskTick));
#endif
            runWithOptions(globalObject, mainCommandLine.get(), success);
        });

    ...
}
```

Follow into the `runJSC` function, it first allocates `vm` object, and then it will call `GlobalObject::create` to initialize the `vm` and `globalObject`.

```c++
// jsc.cpp: 3587
int runJSC(const CommandLine& options, bool isWorker, const Func& func)
{
    ...
    
    VM& vm = VM::create(LargeHeap).leakRef();
    ...
    GlobalObject* globalObject = nullptr;
    {
        ...
        globalObject = GlobalObject::create(vm, GlobalObject::createStructure(vm, jsNull()), options.m_arguments);
        globalObject->setRemoteDebuggingEnabled(options.m_enableRemoteDebugging);
        func(vm, globalObject, success);
        vm.drainMicrotasks();
    }
    ...

```

`GlobalObject::create` is responsible for initialising the `VM` with the required builtins and other runtime setup activities. The related code is shown as below, it register the `runtime builtins` such as `debug` and  `describe` function by calling `addFunction`. It inner calls `JSGlobalObject::init` function, this `init` function initialize most of `js object builtins`, such as `array` and `string` related `builtins`. You can follow `JSGlobalObject::init` function to see how the `builtin` objects are generated and functions are compiled. I won't go into that deep here, but i'll try to explain in another post.

```c++
    // jsc.cpp: 501
		static GlobalObject* create(VM& vm, Structure* structure, const Vector<String>& arguments)
    {
        GlobalObject* object = new (NotNull, allocateCell<GlobalObject>(vm)) GlobalObject(vm, structure);
        object->finishCreation(vm, arguments);
        return object;
    }

		// jsc.cpp: 523
		void finishCreation(VM& vm, const Vector<String>& arguments)
    {
        Base::finishCreation(vm);
        JSC_TO_STRING_TAG_WITHOUT_TRANSITION();

        addFunction(vm, "debug", functionDebug, 1);
        addFunction(vm, "describe", functionDescribe, 1);
        addFunction(vm, "describeArray", functionDescribeArray, 1);
     ...

// runtime/JSGlobalObject.cpp: 2622
void JSGlobalObject::finishCreation(VM& vm)
{
    ...
    init(vm);
    ...
}

// runtime/JSGlobalObject.cpp: 715
void JSGlobalObject::init(VM& vm)
{
    ...
    m_functionPrototype->addFunctionProperties(vm, this, &callFunction, &applyFunction, &hasInstanceSymbolFunction);
    
```

After initialize the `runtime builtins`, `runJSC` function calls the lambda function(forth parameter), remember the forth parameter is `runWithOptions` function, so let's dive into `runWithOptions` function.

In `runWithOptions` function, it will get the js file path, and call `fetchScriptFromLocalFileSystem` to open and read js file content to memory, which will be stored in `scriptBuffer`. 

```c++
// jsc.cpp: 3153
static void runWithOptions(GlobalObject* globalObject, CommandLine& options, bool& success)
{
    ...

    VM& vm = globalObject->vm();
    auto scope = DECLARE_CATCH_SCOPE(vm);
  ...
    for (size_t i = 0; i < scripts.size(); i++) {
        ...
        if (scripts[i].codeSource == Script::CodeSource::File) {
            fileName = scripts[i].argument;
            if (scripts[i].strictMode == Script::StrictMode::Strict)
                scriptBuffer.append("\"use strict\";\n", strlen("\"use strict\";\n"));

            if (isModule) {
                ...
            } else {
                if (!fetchScriptFromLocalFileSystem(fileName, scriptBuffer)) {
                    success = false; // fail early so we can catch missing files
                    return;
                }
            }
        }
      ...        
        bool isLastFile = i == scripts.size() - 1;
        SourceOrigin sourceOrigin { absolutePath(fileName) };
        ...
            JSValue returnValue = evaluate(globalObject, jscSource(scriptBuffer, sourceOrigin , fileName), JSValue(), evaluationException);
            
```

 Before calling `evaluate` function, `runWithOptions`  calls `jscSource` function to build a `SouceCode` object, the `SourceCode` object encapsulates the raw script data which is helpful for parsing the source.

```c++
// jsc.cpp: 1144
static inline SourceCode jscSource(const Vector& utf8, const SourceOrigin& sourceOrigin, const String& filename)
{
    // FIXME: This should use an absolute file URL https://bugs.webkit.org/show_bug.cgi?id=193077
    String str = stringFromUTF(utf8);
    return jscSource(str, sourceOrigin, filename);
}

// jsc.cpp: 1138
static inline SourceCode jscSource(const String& source, const SourceOrigin& sourceOrigin, String sourceURL = String(), const TextPosition& startPosition = TextPosition(), SourceProviderSourceType sourceType = SourceProviderSourceType::Program)
{
    return SourceCode(ShellSourceProvider::create(source, sourceOrigin, WTFMove(sourceURL), startPosition, sourceType), startPosition.m_line.oneBasedInt(), startPosition.m_column.oneBasedInt());
}
```

Right now, the runtime has been set up and the js source has been loaded into memory(`source`) , `runWithOptions`  will call `evaluate` function to interpreter the js, so we can go into the next part.

## Parse to AST

Now that all the runtime things are ready, we can start to handle the source code, as we can see, the `runWithOptions` function calls `evaluate` function to parse and execute js. Follow the `evaluate` function, we can see it inner calls `executeProgram` directly.

```c++
// jsc.cpp: 3153
static void runWithOptions(GlobalObject* globalObject, CommandLine& options, bool& success)
{
        ...
            JSValue returnValue = evaluate(globalObject, jscSource(scriptBuffer, sourceOrigin , fileName), JSValue(), evaluationException);

// runtime/Completion.cpp: 126
JSValue evaluate(JSGlobalObject* globalObject, const SourceCode& source, JSValue thisValue, NakedPtr<Exception>& returnedException)
{
    ...
    if (!thisValue || thisValue.isUndefinedOrNull())
        thisValue = globalObject;
    JSObject* thisObj = jsCast<JSObject*>(thisValue.toThis(globalObject, ECMAMode::sloppy()));
    JSValue result = vm.interpreter->executeProgram(source, globalObject, thisObj);

    ...
}
```

Get into `executeProgram` function, it responsible for parsing and executing the js source, which can be concluded as 6 parts: 

1. `ProgramExecutable::create` to allocate `ProgramExecutable` object, which inner allocate some important object.
2. check it's `JSON ` source code or not, if it is, parse as json, for we don't care about that part, just ignore it.
3. call  `program->initializeGlobalProperties`  to compile the js source to `unlinked` bytecode.
4. call `program->prepareForExecution` to link the `unlinked` bytecode to `linked` bytecode.
5. call `protoCallFrame.init` to set up the entry pointer for `interpreter`.
6. call `jitCode->execute` to interpreter the `bytecode`.

In this section we care about the first 3 steps, i'll explain it in detail here.

```c++
// interpreter/Interpreter.cpp: 709
JSValue Interpreter::executeProgram(const SourceCode& source, JSGlobalObject*, JSObject* thisObj)
{
    ...
    ProgramExecutable* program = ProgramExecutable::create(globalObject, source);
  
    ...

    // First check if the "program" is actually just a JSON object. If so,
    // we'll handle the JSON object here. Else, we'll handle real JS code
    // below at failedJSONP.

    Vector<JSONPData> JSONPData;
    bool parseResult;
    StringView programSource = program->source().view();
    if (programSource.isNull())
        return jsUndefined();
    if (programSource.is8Bit()) {
        LiteralParser<LChar> literalParser(globalObject, programSource.characters8(), programSource.length(), JSONP);
        parseResult = literalParser.tryJSONPParse(JSONPData, globalObject->globalObjectMethodTable()->supportsRichSourceInfo(globalObject));
    } ...

    RETURN_IF_EXCEPTION(throwScope, { });
    if (parseResult) {
        ...
failedJSONP:
    // If we get here, then we have already proven that the script is not a JSON
    // object.

    // Compile source to bytecode if necessary:
    JSObject* error = program->initializeGlobalProperties(vm, globalObject, scope);
    ...

    ProgramCodeBlock* codeBlock;
    {
        CodeBlock* tempCodeBlock;
        program->prepareForExecution<ProgramExecutable>(vm, nullptr, scope, CodeForCall, tempCodeBlock);
        RETURN_IF_EXCEPTION(throwScope, checkedReturn(throwScope.exception()));

        codeBlock = jsCast<ProgramCodeBlock*>(tempCodeBlock);
        ASSERT(codeBlock && codeBlock->numParameters() == 1); // 1 parameter for 'this'.
    }

    RefPtr<JITCode> jitCode;
    ProtoCallFrame protoCallFrame;
    {
        DisallowGC disallowGC; // Ensure no GC happens. GC can replace CodeBlock in Executable.
        jitCode = program->generatedJITCode();
        protoCallFrame.init(codeBlock, globalObject, globalCallee, thisObj, 1);
    }

    // Execute the code:
    throwScope.release();
    ASSERT(jitCode == program->generatedJITCode().ptr());
    JSValue result = jitCode->execute(&vm, &protoCallFrame);
    return checkedReturn(result);
}
```

 `Interpreter::executeProgram` first call `ProgramExecutable::create` to allocate a `ProgramExecutable` object. In `ProgramExecutable`'s constructor, it will initialize its base class which is `GlobalExecutable` object. In `GlobalExecutable` object's constructor, it will initialize its base class which is `ScriptExecutable` object, which will finally initialize `ExecutableBase` object. All the upper objects are important in the running process, some objects are also useful for exploiting, we should keep in mind here.

```c++
    // runtime/ProgramExecutable.h: 45
		static ProgramExecutable* create(JSGlobalObject* globalObject, const SourceCode& source)
    {
        VM& vm = getVM(globalObject);
        ProgramExecutable* executable = new (NotNull, allocateCell<ProgramExecutable>(vm)) ProgramExecutable(globalObject, source);
        ...
        return executable;
    }

// runtime/ProgramExecutable.cpp: 37
ProgramExecutable::ProgramExecutable(JSGlobalObject* globalObject, const SourceCode& source)
    : Base(globalObject->vm().programExecutableStructure.get(), globalObject->vm(), source, false, DerivedContextType::None, false, false, EvalContextType::None, NoIntrinsic)
{
    ...
}

// runtime/GlobalExecutable.h: 52
    GlobalExecutable(Structure* structure, VM& vm, const SourceCode& sourceCode, bool isInStrictContext, DerivedContextType derivedContextType, bool isInArrowFunctionContext, bool isInsideOrdinaryFunction, EvalContextType evalContextType, Intrinsic intrinsic)
        : Base(structure, vm, sourceCode, isInStrictContext ? StrictModeLexicalFeature : NoLexicalFeatures, derivedContextType, isInArrowFunctionContext, isInsideOrdinaryFunction, evalContextType, intrinsic)
    {
    }

    ...
};

// runtime/ScriptExecutable.cpp: 49
ScriptExecutable::ScriptExecutable(Structure* structure, VM& vm, const SourceCode& source, LexicalScopeFeatures lexicalScopeFeatures, DerivedContextType derivedContextType, bool isInArrowFunctionContext, bool isInsideOrdinaryFunction, EvalContextType evalContextType, Intrinsic intrinsic)
    : ExecutableBase(vm, structure)
    , m_source(source)
    , m_intrinsic(intrinsic)
    , m_features(NoFeatures)
    , m_lexicalScopeFeatures(lexicalScopeFeatures)
    , m_hasCapturedVariables(false)
    , m_neverInline(false)
    , m_neverOptimize(false)
    , m_neverFTLOptimize(false)
    , m_isArrowFunctionContext(isInArrowFunctionContext)
    , m_canUseOSRExitFuzzing(true)
    , m_codeForGeneratorBodyWasGenerated(false)
    , m_isInsideOrdinaryFunction(isInsideOrdinaryFunction)
    , m_derivedContextType(static_cast<unsigned>(derivedContextType))
    , m_evalContextType(static_cast<unsigned>(evalContextType))
{
}
```

After allocating the related objects, `Interpreter::executeProgram` checks the source code whether is json format or not, as we said before, we don't care about that, so i'll skip this part of code.

And then as the comment shows, `Interpreter::executeProgram` function calls `program->initializeGlobalProperties`  to compile source to `unlinked` bytecode. What we focus on in this part is that how to parse the source to `AST`, so we have arrived the key point in this section which is the `initializeGlobalProperties` function.

Let's check the `initializeGlobalProperties` function, it calls `getUnlinkedProgramCodeBlock` function to generate `UnlinkedProgramCodeBlock` which is used to store `unlinked` bytecode, and then do some additional checks, we just take care about `getUnlinkedProgramCodeBlock` function here.

```c++
// runtime/ProgramExecutable.cpp: 67
JSObject* ProgramExecutable::initializeGlobalProperties(VM& vm, JSGlobalObject* globalObject, JSScope* scope)
{
    ...
    OptionSet<CodeGenerationMode> codeGenerationMode = globalObject->defaultCodeGenerationMode();
    UnlinkedProgramCodeBlock* unlinkedCodeBlock = vm.codeCache()->getUnlinkedProgramCodeBlock(
        vm, this, source(), strictMode, codeGenerationMode, error);
  ...
  {
        // Check for intersection of "var" and "let"/"const"/"class"
        for (auto& entry : lexicalDeclarations) {
            if (variableDeclarations.contains(entry.key))
                return createSyntaxError(globalObject, makeString("Can't create duplicate variable: '", String(entry.key.get()), "'"));
        }
```

Follow the code execution flow, we can see it forms the below call stack chain `CodeCache::getUnlinkedProgramCodeBlock->CodeCache::getUnlinkedGlobalCodeBlock->generateUnlinkedCodeBlock->generateUnlinkedCodeBlock->generateUnlinkedCodeBlockImpl`. The last function `generateUnlinkedCodeBlockImpl` is the final function which is responsible for generating the `unlinked` bytecode.

```c++
// runtime/CodeCache.cpp: 189
UnlinkedProgramCodeBlock* CodeCache::getUnlinkedProgramCodeBlock(VM& vm, ProgramExecutable* executable, const SourceCode& source, JSParserStrictMode strictMode, OptionSet<CodeGenerationMode> codeGenerationMode, ParserError& error)
{
    return getUnlinkedGlobalCodeBlock<UnlinkedProgramCodeBlock>(vm, executable, source, strictMode, JSParserScriptMode::Classic, codeGenerationMode, error, EvalContextType::None);
}
...

 // runtime/CodeCache.cpp: 154
template <class UnlinkedCodeBlockType, class ExecutableType>
UnlinkedCodeBlockType* CodeCache::getUnlinkedGlobalCodeBlock(VM& vm, ExecutableType* executable, const SourceCode& source, JSParserStrictMode strictMode, JSParserScriptMode scriptMode, OptionSet<CodeGenerationMode> codeGenerationMode, ParserError& error, EvalContextType evalContextType)
{
    ...

    unlinkedCodeBlock = generateUnlinkedCodeBlock<UnlinkedCodeBlockType, ExecutableType>(vm, executable, source, strictMode, scriptMode, codeGenerationMode, error, evalContextType);

    ...

    return unlinkedCodeBlock;
}

// runtime/CodeCache.cpp: 119
template <class UnlinkedCodeBlockType, class ExecutableType>
UnlinkedCodeBlockType* generateUnlinkedCodeBlock(VM& vm, ExecutableType* executable, const SourceCode& source, JSParserStrictMode strictMode, JSParserScriptMode scriptMode, OptionSet<CodeGenerationMode> codeGenerationMode, ParserError& error, EvalContextType evalContextType, const TDZEnvironment* variablesUnderTDZ = nullptr, const PrivateNameEnvironment* privateNameEnvironment = nullptr)
{
    return generateUnlinkedCodeBlockImpl<UnlinkedCodeBlockType, ExecutableType>(vm, source, strictMode, scriptMode, codeGenerationMode, error, evalContextType, executable->derivedContextType(), executable->isArrowFunctionContext(), variablesUnderTDZ, privateNameEnvironment, executable);
}
```

The call `stack` in gdb is shown as below:

```asm
pwndbg> bt
#0  JSC::generateUnlinkedCodeBlockImpl<JSC::UnlinkedProgramCodeBlock, JSC::ProgramExecutable> (vm=..., source=..., strictMode=JSC::JSParserStrictMode::NotStrict, scriptMode=JSC::JSParserScriptMode::Classic, codeGenerationMode=..., error=..., evalContextType=JSC::EvalContextType::None, derivedContextType=JSC::DerivedContextType::None, isArrowFunctionContext=0x0, variablesUnderTDZ=0x0, privateNameEnvironment=0x0, executable=0x7ffff17fa848) at ../../Source/JavaScriptCore/runtime/CodeCache.cpp:77
#1  0x00007ffff5d037c1 in JSC::generateUnlinkedCodeBlock<JSC::UnlinkedProgramCodeBlock, JSC::ProgramExecutable> (vm=..., executable=0x7ffff17fa848, source=..., strictMode=JSC::JSParserStrictMode::NotStrict, scriptMode=JSC::JSParserScriptMode::Classic, codeGenerationMode=..., error=..., evalContextType=JSC::EvalContextType::None, variablesUnderTDZ=0x0, privateNameEnvironment=0x0) at ../../Source/JavaScriptCore/runtime/CodeCache.cpp:122
#2  0x00007ffff5cf66d4 in JSC::CodeCache::getUnlinkedGlobalCodeBlock<JSC::UnlinkedProgramCodeBlock, JSC::ProgramExecutable> (this=0x7ffff17e70d8, vm=..., executable=0x7ffff17fa848, source=..., strictMode=JSC::JSParserStrictMode::NotStrict, scriptMode=JSC::JSParserScriptMode::Classic, codeGenerationMode=..., error=..., evalContextType=JSC::EvalContextType::None) at ../../Source/JavaScriptCore/runtime/CodeCache.cpp:176
#3  0x00007ffff5ce2c38 in JSC::CodeCache::getUnlinkedProgramCodeBlock (this=0x7ffff17e70d8, vm=..., executable=0x7ffff17fa848, source=..., strictMode=JSC::JSParserStrictMode::NotStrict, codeGenerationMode=..., error=...) at ../../Source/JavaScriptCore/runtime/CodeCache.cpp:191
#4  0x00007ffff601c50a in JSC::ProgramExecutable::initializeGlobalProperties (this=0x7ffff17fa848, vm=..., globalObject=0x7fffb11f6068, scope=0x7ffff17b7068) at ../../Source/JavaScriptCore/runtime/ProgramExecutable.cpp:79
#5  0x00007ffff5996d1a in JSC::Interpreter::executeProgram (this=0x7ffff17fe248, source=..., thisObj=0x7ffff17ac608) at ../../Source/JavaScriptCore/interpreter/Interpreter.cpp:864
#6  0x00007ffff5d3e625 in JSC::evaluate (globalObject=0x7fffb11f6068, source=..., thisValue=..., returnedException=...) at ../../Source/JavaScriptCore/runtime/Completion.cpp:137
#7  0x0000555555579d72 in runWithOptions (globalObject=0x7fffb11f6068, options=..., success=@0x7fffffffdf82: 0x1) at ../../Source/JavaScriptCore/jsc.cpp:3216
#8  0x000055555557b40c in <lambda(JSC::VM&, GlobalObject*, bool&)>::operator()(JSC::VM &, GlobalObject *, bool &) const (__closure=0x7fffffffe100, vm=..., globalObject=0x7fffb11f6068, success=@0x7fffffffdf82: 0x1) at ../../Source/JavaScriptCore/jsc.cpp:3785
#9  0x000055555557d780 in runJSC<jscmain(int, char**)::<lambda(JSC::VM&, GlobalObject*, bool&)> >(const CommandLine &, bool, const <lambda(JSC::VM&, GlobalObject*, bool&)> &) (options=..., isWorker=0x0, func=...) at ../../Source/JavaScriptCore/jsc.cpp:3607
#10 0x000055555557b559 in jscmain (argc=0x3, argv=0x7fffffffe248) at ../../Source/JavaScriptCore/jsc.cpp:3778
#11 0x000055555557849a in main (argc=0x3, argv=0x7fffffffe248) at ../../Source/JavaScriptCore/jsc.cpp:3004
#12 0x00007ffff40940b3 in __libc_start_main (main=0x55555557846a <main(int, char**)>, argc=0x3, argv=0x7fffffffe248, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe238) at ../csu/libc-start.c:308
#13 0x00005555555649be in _start ()
```

Now we get into `generateUnlinkedCodeBlockImpl`, this function can be devided into two part:

* the first part is `parse<RootNode>`, which is responsible for lexing and parsing the souce code to `AST`.
* the second part is `BytecodeGenerator::generate`, which is responsible for generating the `unlinked` bytecode from `AST`.

```c++
// runtime/CodeCache.cpp: 73
template <class UnlinkedCodeBlockType, class ExecutableType = ScriptExecutable>
UnlinkedCodeBlockType* generateUnlinkedCodeBlockImpl(VM& vm, const SourceCode& source, JSParserStrictMode 
...
{
    ...

    std::unique_ptr<RootNode> rootNode = parse<RootNode>(
        vm, source, Identifier(), JSParserBuiltinMode::NotBuiltin, strictMode, scriptMode, CacheTypes<UnlinkedCodeBlockType>::parseMode, SuperBinding::NotNeeded, error, nullptr, ConstructorKind::None, derivedContextType, evalContextType, nullptr, privateNameEnvironment, nullptr, isInsideOrdinaryFunction);

    if (!rootNode)
        return nullptr;

    ...

    UnlinkedCodeBlockType* unlinkedCodeBlock = UnlinkedCodeBlockType::create(vm, executableInfo, codeGenerationMode);
    ...
    error = BytecodeGenerator::generate(vm, rootNode.get(), source, unlinkedCodeBlock, codeGenerationMode, parentVariablesUnderTDZ, privateNameEnvironment);

    if (error.isValid())
        return nullptr;

    return unlinkedCodeBlock;
}
```

In this section we focus on the first part which is the `parse` function, just check out this function.

In the `parse` function, it first calls `Parser` constructor to initialize a `parser` and then calls `parser.parse` function to `lex` and `parse` the source code to `AST`.

```c++
// parser/Parser.h: 2191
template <class ParsedNode>
std::unique_ptr<ParsedNode> parse(
    ...

    std::unique_ptr<ParsedNode> result;
    if (source.provider()->source().is8Bit()) {
        Parser<Lexer<LChar>> parser(vm, source, builtinMode, strictMode, scriptMode, parseMode, superBinding, defaultConstructorKindForTopLevelFunction, derivedContextType, isEvalNode<ParsedNode>(), evalContextType, debuggerParseData, isInsideOrdinaryFunction);
        result = parser.parse<ParsedNode>(error, name, isEvalNode<ParsedNode>() ? ParsingContext::Eval : ParsingContext::Program, std::nullopt, parentScopePrivateNames, classFieldLocations);
        ...
    } else {
        ...

    return result;
}
```

So first let's go to see how the `parser` is initialized, it initializes a `m_lexer` which is used to `lex` the source code. It also initializes a `m_token` which is used to store the token that the `m_lexer` lexed out.

```c++
// parser/Parser.cpp: 130
template <typename LexerType>
Parser<LexerType>::Parser(VM& vm, const SourceCode& source, JSParserBuiltinMode builtinMode, 
...
{
    m_lexer = makeUnique<LexerType>(vm, builtinMode, scriptMode);
    m_lexer->setCode(source, &m_parserArena);
    m_token.m_location.line = source.firstLine().oneBasedInt();
    m_token.m_location.startOffset = source.startOffset();
    m_token.m_location.endOffset = source.startOffset();
    m_token.m_location.lineStartOffset = source.startOffset();
    m_functionCache = vm.addSourceProviderCache(source.provider());
    m_expressionErrorClassifier = nullptr;

    ...

    next();
}
```

Then it calls the `next` function to `lex` the first token out from the source code. `next` function can be said to be a key function in lexing. It takes the source as input and lex a `m_token` out. Get into the `next` function, we can see it calls `m_lexer->lex` to lex the `source`.

```c++
    // parser/Parser.h: 1490
		ALWAYS_INLINE void next(OptionSet<LexerFlags> lexerFlags = { })
    {
        int lastLine = m_token.m_location.line;
        int lastTokenEnd = m_token.m_location.endOffset;
        int lastTokenLineStart = m_token.m_location.lineStartOffset;
        m_lastTokenEndPosition = JSTextPosition(lastLine, lastTokenEnd, lastTokenLineStart);
        m_lexer->setLastLineNumber(lastLine);
        m_token.m_type = m_lexer->lex(&m_token, lexerFlags, strictMode());
    }
```

Follow into the `lex` function, it directly calls `lexWithoutClearingLineTerminator` function.

```c++
// parser/Lexer.h: 409
template <typename T>
ALWAYS_INLINE JSTokenType Lexer<T>::lex(JSToken* tokenRecord, OptionSet<LexerFlags> lexerFlags, bool strictMode)
{
    m_hasLineTerminatorBeforeToken = false;
    return lexWithoutClearingLineTerminator(tokenRecord, lexerFlags, strictMode);
}
```

Dive into `lexWithoutClearingLineTerminator` function, it will call `skipWhitespace` to  skip the white space, and get the type according to the `m_current`, which is the character that being parsed, and then lex the word out according to the type.

```c++
// parser/Lexer.cpp: 1907
template <typename T>
JSTokenType Lexer<T>::lexWithoutClearingLineTerminator(JSToken* tokenRecord, OptionSet<LexerFlags> lexerFlags, bool strictMode)
{
    ...

start:
    skipWhitespace();

    ...

    CharacterType type;
    if (LIKELY(isLatin1(m_current)))
        type = static_cast<CharacterType>(typesOfLatin1Characters[m_current]);
    else {
        UChar32 codePoint;
        U16_GET(m_code, 0, 0, m_codeEnd - m_code, codePoint);
        if (isNonLatin1IdentStart(codePoint))
            type = CharacterIdentifierStart;
        else if (isLineTerminator(m_current))
            type = CharacterLineTerminator;
        else
            type = CharacterInvalid;
    }

    switch (type) {
    case CharacterGreater:
        shift();
    ...
    case CharacterGreater:
        shift();
        ...
    case CharacterEqual: 
    ...
    case CharacterLess:
    ...
    case CharacterExclamationMark:
    ...
    // parser/Lexer.cpp: 2489
    case CharacterIdentifierStart: {
        if constexpr (ASSERT_ENABLED) {
            UChar32 codePoint;
            U16_GET(m_code, 0, 0, m_codeEnd - m_code, codePoint);
            ASSERT(isIdentStart(codePoint));
        }
        FALLTHROUGH;
    }
    case CharacterBackSlash:
        parseIdent:
        if (lexerFlags.contains(LexerFlags::DontBuildKeywords))
            token = parseIdentifier<false>(tokenData, lexerFlags, strictMode);
        else
            token = parseIdentifier<true>(tokenData, lexerFlags, strictMode);
        break;
```

Take the `demo.js`'s first line `let x = 10` as a example, when the `m_current` is `l`, the type is `CharacterIdentifierStart`, and it will call `parseIdentifier` to parse a `identifier`. `parseIdentifier` first calls `parseKeyword` function to get the `keyword` out, as we can see, the `let` is mapped to `LET` keyword. Now we finished the lex of first word `let` and understand the mechanism of `next` function.

```c++
// parser/Lexer.cpp: 936
template <>
template <bool shouldCreateIdentifier> ALWAYS_INLINE JSTokenType Lexer<LChar>::parseIdentifier(JSTokenData* tokenData, OptionSet<LexerFlags> lexerFlags, bool strictMode)
{
    ...
    if ((remaining >= maxTokenLength) && !lexerFlags.contains(LexerFlags::IgnoreReservedWords)) {
        JSTokenType keyword = parseKeyword<shouldCreateIdentifier>(tokenData);
        if (keyword != IDENT) {
            ASSERT((!shouldCreateIdentifier) || tokenData->ident);
            return keyword == RESERVED_IF_STRICT && !strictMode ? IDENT : keyword;
        }
    }

...
// JavaScriptCore/KerywordLookup.h: 462
template <>
template <bool shouldCreateIdentifier> ALWAYS_INLINE JSTokenType Lexer<LChar>::parseKeyword(JSTokenData* data)
{
    ASSERT(m_codeEnd - m_code >= maxTokenLength);

    const LChar* code = m_code;
    if (code[0] == 'f') {
        if (COMPARE_7CHARS(code + 1, 'u', 'n', 'c', 't', 'i', 'o', 'n')) {
            if (LIKELY(cannotBeIdentPartOrEscapeStart(code[8]))) {
                internalShift<8>();
                if (shouldCreateIdentifier)
                    data->ident = &m_vm.propertyNames->functionKeyword;
                return FUNCTION;
            }
     ...    
     } else if (COMPARE_3CHARS(code, 'l', 'e', 't')) {
        if (LIKELY(cannotBeIdentPartOrEscapeStart(code[3]))) {
            internalShift<3>();
            if (shouldCreateIdentifier)
                data->ident = &m_vm.propertyNames->letKeyword;
            return LET;
        }
    }
```

So we finished the initialization of `parser`, we can go back the `parse` function and see how to build the `AST` in  `parser.parse` function.

Get into the `parser.parse` function, we can see it inner calls `parseInner` function to parse the source.

```c++
// parser/Parser.h: 2100
std::unique_ptr<ParsedNode> Parser<LexerType>::parse(ParserError& error, const Identifier& calleeName, ParsingContext parsingContext, std::optional<int> functionConstructorParametersEndPosition, const PrivateNameEnvironment* parentScopePrivateNames, const FixedVector<JSTextPosition>* classFieldLocations)
{
    ...
    auto parseResult = parseInner(calleeName, parsingContext, functionConstructorParametersEndPosition, classFieldLocations, parentScopePrivateNames);

    ...

    return result;
}
```

In the `parseInner` function, it first build a `context` object to store the `AST` result, which is a `ASTBuilder` class. And then because the `demo`  is not a function, just a program, so `parseInner` invokes `parseSourceElements` to generate the `AST`, after finishing the generation of the `AST`, it will also perform some additional check for the `AST`, and finally return the parse result.

```c++
// parser/Parser.cpp: 223
template <typename LexerType>
Expected<typename Parser<LexerType>::ParseInnerResult, String> Parser<LexerType>::parseInner(const Identifier& calleeName, ParsingContext parsingContext, std::optional<int> functionConstructorParametersEndPosition, const FixedVector<JSTextPosition>* classFieldLocations, const PrivateNameEnvironment* parentScopePrivateNames)
{
    ASTBuilder context(const_cast<VM&>(m_vm), m_parserArena, const_cast<SourceCode*>(m_source));
    ...
    // The only way we can error this early is if we reparse a function and we run out of stack space.
    if (!hasError()) {
        if (isAsyncFunctionWrapperParseMode(parseMode))
            ...
        } else
            sourceElements = parseSourceElements(context, CheckForStrictMode);
    }

    bool validEnding = consume(EOFTOK);
    if (!sourceElements || !validEnding)
        return makeUnexpected(hasError() ? m_errorMessage : "Parser error"_s);

    ...

    return ParseInnerResult { parameters, sourceElements, scope->takeFunctionDeclarations(), scope->takeDeclaredVariables(), scope->takeLexicalEnvironment(), WTFMove(sloppyModeHoistedFunctions), features, context.numConstants() };
}
```

So we need get into `parseSourceElements` function to see how it build the `AST` tree. The `context` first calls `createSourceElements`  function to allocate a `sourceElements` object, and then call `parseStatementListItem` function to parse the source. The  `parseStatementListItem` takes the source as input, and output the next `AST` node, the `AST` node is named as `statement`  in `jsc`. Once the `statement` has been generated, it will be appended into the `sourceElements`, which eventually forms the `AST` tree.

```c++
// parser/Parser.cpp: 401
template <typename LexerType>
template <class TreeBuilder> TreeSourceElements Parser<LexerType>::parseSourceElements(TreeBuilder& context, SourceElementsMode mode)
{
    ...
    TreeSourceElements sourceElements = context.createSourceElements();
    ...
    
    while (TreeStatement statement = parseStatementListItem(context, directive, &directiveLiteralLength)) {
        if (shouldCheckForUseStrict) {
            ...
        }
        context.appendStatement(sourceElements, statement);
    }

    propagateError();
    return sourceElements;
}
```

The function `parseStatementListItem` is responsible for parsing the source code to construct a `statement`.

In `parseStatementListItem` function, it will perform the corresponding parse and generate the `statement` according to the `m_token.m_type`, which is the `key` word that the `next` function returns. 

```c++
// parser/Parser.cpp: 700
template <typename LexerType>
template <class TreeBuilder> TreeStatement Parser<LexerType>::parseStatementListItem(TreeBuilder& context, const Identifier*& directive, unsigned* directiveLiteralLength)
{
    ...

    switch (m_token.m_type) {
    case CONSTTOKEN:
        result = parseVariableDeclaration(context, DeclarationType::ConstDeclaration);
        shouldSetPauseLocation = true;
        break;
    case LET: {
        bool shouldParseVariableDeclaration = true;
        ...
        if (shouldParseVariableDeclaration)
            result = parseVariableDeclaration(context, DeclarationType::LetDeclaration);
        else {
            bool allowFunctionDeclarationAsStatement = true;
            result = parseExpressionOrLabelStatement(context, allowFunctionDeclarationAsStatement);
        }
        shouldSetPauseLocation = !context.shouldSkipPauseLocation(result);
        break;
    }
```

In our `demo`, the `m_token.m_type` is `LET`, it will call `parseVariableDeclaration` to generate the variable declaration related `statement`.

```c++
template <typename LexerType>
template <class TreeBuilder> TreeStatement Parser<LexerType>::parseVariableDeclaration(TreeBuilder& context, DeclarationType declarationType, ExportType exportType)
{
    ASSERT(match(VAR) || match(LET) || match(CONSTTOKEN));
    JSTokenLocation location(tokenLocation());
    int start = tokenLine();
    int end = 0;
    int scratch;
    TreeDestructuringPattern scratch1 = 0;
    TreeExpression scratch2 = 0;
    JSTextPosition scratch3;
    bool scratchBool;
    TreeExpression variableDecls = parseVariableDeclarationList(context, scratch, scratch1, scratch2, scratch3, scratch3, scratch3, VarDeclarationContext, declarationType, exportType, scratchBool);
    propagateError();
    failIfFalse(autoSemiColon(), "Expected ';' after variable declaration");
    
    return context.createDeclarationStatement(location, variableDecls, start, end);
}
```

Continue to go with `let x = 10` as the example, the `parseVariableDeclarationList` will first creates a `AssignmentContext`, and then calls `next` to parse the `x` as `Identifier* name`. And then calls `next` to parse the `=`, which knows that it has the `initializer`. For it has the `initializer`, it need to call `parseAssignmentExpression` function to build the `initializer`(`rhs`). Once all the words are parsed, the `createAssignResolve` function will be called to generate the `VariableDeclaration statement` (`AST` node) and return.

```c++
// parser/Parser.cpp: 861
template <typename LexerType>
template <class TreeBuilder> TreeExpression Parser<LexerType>::parseVariableDeclarationList(TreeBuilder& 
...
{
    ...
    AssignmentContext assignmentContext = assignmentContextFromDeclarationType(declarationType);
    do {
        ...
        next();
        ...
        declarations++;
        bool hasInitializer = false;

        failIfTrue(match(PRIVATENAME), "Cannot use a private name to declare a variable");
        if (matchSpecIdentifier()) {
            ...
            const Identifier* name = m_token.m_data.ident;
            lastIdent = name;
            lastIdentToken = m_token;
            next();
            hasInitializer = match(EQUAL);
            DeclarationResultMask declarationResult = declareVariable(name, declarationType);
            ...

            if (hasInitializer) {
                ...
                next(TreeBuilder::DontBuildStrings); // consume '='
                ...
                TreeExpression initializer = parseAssignmentExpression(context);
                ...
                
                node = context.createAssignResolve(location, *name, initializer, varStart, varDivot, lastTokenEndPosition(), assignmentContext);
            } else {
                ...
    return head;
}
```

One `statement` has been built, the `parseSourceElements` will continue to traverse all the other source code to build the `AST` tree.

`parseSourceElements` returns by creating an AST of `ParsedNode` elements. When `parse` returns without any syntax or semantic parsing errors, we have a valid AST with `rootNode` pointing to the root of the tree.

## Generate unlinked bytecode

As said before, i assume you are familiar with bytecode, so i won't explain too much about the bytecode, if you need, just check the official post  [A New Bytecode Format for JavaScriptCore](https://webkit.org/blog/9329/a-new-bytecode-format-for-javascriptcore/).

But to explain it more clearly, we need to give out the `demo.js`'s bytecode here and explain a little about the bytecode. Add command line `-d` in the jsc, it will output the `bytecode` to `stderr`. The first line gives out the basic information, `18` instruction and `212` bytes. the `18` instructions are follow the first line, the number in the `[]` means the offset in the `bytecode stream`. And the `Identifiers`, and `Constants` are followed behind.

```asm
$ ~/work/jsc/engine/WebKit/WebKitBuild/Debug/bin/jsc -d demo.js
<global>#CR3m3u:[0x7f95897c0000->0x7f95ca1fa848, NoneGlobal, 96]: 18 instructions (0 16-bit instructions, 0 32-bit instructions, 10 instructions with metadata); 212 bytes (116 metadata bytes); 1 parameter(s); 12 callee register(s); 6 variable(s); scope at loc4

bb#1
Predecessors: [ ]
[   0] enter
[   1] get_scope          dst:loc4
[   3] mov                dst:loc5, src:loc4
[   6] check_traps
[   7] mov                dst:loc6, src:Undefined(const0)
[  10] resolve_scope      dst:loc7, scope:loc4, var:0, resolveType:GlobalProperty, localScopeDepth:0
[  17] put_to_scope       scope:loc7, var:0, value:Int32: 10(const1), getPutInfo:1048576<DoNotThrowIfNotFound|GlobalProperty|Initialization|NotStrictMode>, symbolTableOrScopeDepth:0, offset:0
[  25] resolve_scope      dst:loc7, scope:loc4, var:1, resolveType:GlobalProperty, localScopeDepth:0
[  32] put_to_scope       scope:loc7, var:1, value:Int32: 20(const2), getPutInfo:1048576<DoNotThrowIfNotFound|GlobalProperty|Initialization|NotStrictMode>, symbolTableOrScopeDepth:0, offset:0
[  40] resolve_scope      dst:loc7, scope:loc4, var:2, resolveType:GlobalProperty, localScopeDepth:0
[  47] resolve_scope      dst:loc8, scope:loc4, var:0, resolveType:GlobalProperty, localScopeDepth:0
[  54] get_from_scope     dst:loc9, scope:loc8, var:0, getPutInfo:2048<ThrowIfNotFound|GlobalProperty|NotInitialization|NotStrictMode>, localScopeDepth:0, offset:0
[  62] mov                dst:loc8, src:loc9
[  65] resolve_scope      dst:loc9, scope:loc4, var:1, resolveType:GlobalProperty, localScopeDepth:0
[  72] get_from_scope     dst:loc10, scope:loc9, var:1, getPutInfo:2048<ThrowIfNotFound|GlobalProperty|NotInitialization|NotStrictMode>, localScopeDepth:0, offset:0
[  80] add                dst:loc8, lhs:loc8, rhs:loc10, profileIndex:0, operandTypes:OperandTypes(126, 126)
[  86] put_to_scope       scope:loc7, var:2, value:loc8, getPutInfo:1048576<DoNotThrowIfNotFound|GlobalProperty|Initialization|NotStrictMode>, symbolTableOrScopeDepth:0, offset:0
[  94] end                value:loc6
Successors: [ ]

Identifiers:
  id0 = x
  id1 = y
  id2 = z

Constants:
   k0 = Undefined
   k1 = Int32: 10: in source as integer
   k2 = Int32: 20: in source as integer

End: undefined
```

Now we can continue to explain the generation of `unlinked` bytecode. We have finished the analysis of Parsing js source to `AST`, the `parse` function goes back to `generateUnlinkedCodeBlockImpl`, and `generateUnlinkedCodeBlockImpl` invokes `UnlinkedCodeBlockType::create` to allocate the `unlinkedCodeBlock` object which is used to store the `unlinked` bytecode, and finally it calls `BytecodeGenerator::generate` to generate the `unlinked` bytecode. So in this section, the most important function is `BytecodeGenerator::generate`.

```c++
// runtime/CodeCache.cpp: 73
template <class UnlinkedCodeBlockType, class ExecutableType = ScriptExecutable>
UnlinkedCodeBlockType* generateUnlinkedCodeBlockImpl(VM& vm, const SourceCode& source, JSParserStrictMode 
...
{
    ...

    std::unique_ptr<RootNode> rootNode = parse<RootNode>(
        vm, source, Identifier(), JSParserBuiltinMode::NotBuiltin, strictMode, scriptMode, CacheTypes<UnlinkedCodeBlockType>::parseMode, SuperBinding::NotNeeded, error, nullptr, ConstructorKind::None, derivedContextType, evalContextType, nullptr, privateNameEnvironment, nullptr, isInsideOrdinaryFunction);

    if (!rootNode)
        return nullptr;

    ...

    UnlinkedCodeBlockType* unlinkedCodeBlock = UnlinkedCodeBlockType::create(vm, executableInfo, codeGenerationMode);
    ...
    error = BytecodeGenerator::generate(vm, rootNode.get(), source, unlinkedCodeBlock, codeGenerationMode, parentVariablesUnderTDZ, privateNameEnvironment);

    if (error.isValid())
        return nullptr;

    return unlinkedCodeBlock;
}
```

Dive into `BytecodeGenerator::generate` funciton, it will first allocate a `bytecodeGenerator`, and then calls `bytecodeGenerator->generate` function to generate the `unlinked` bytecode.

```c++
        // bytecompiler/BytecodeGenerator.h: 378
				template<typename Node, typename UnlinkedCodeBlock>
        static ParserError generate(VM& vm, Node* node, const SourceCode& sourceCode, UnlinkedCodeBlock* unlinkedCodeBlock, OptionSet<CodeGenerationMode> codeGenerationMode, const RefPtr<TDZEnvironmentLink>& parentScopeTDZVariables, const PrivateNameEnvironment* privateNameEnvironment)
        {
            ...
            auto bytecodeGenerator = makeUnique<BytecodeGenerator>(vm, node, unlinkedCodeBlock, codeGenerationMode, parentScopeTDZVariables, privateNameEnvironment);
            unsigned size;
            auto result = bytecodeGenerator->generate(size);

            ...
            return result;
        }
```

The `bytecodeGenerator` is initialized with supplied `AST` tree, and emit the program prologue. `emitEnter` emits `enter` bytecode and `emitCheckTraps` emits `check_traps` bytecode.

```c++
// bytecompiler/BytecodeGenerator.cpp: 295
BytecodeGenerator::BytecodeGenerator(VM& vm, ProgramNode* programNode, UnlinkedProgramCodeBlock* codeBlock, OptionSet<CodeGenerationMode> codeGenerationMode, const RefPtr<TDZEnvironmentLink>& parentScopeTDZVariables, const PrivateNameEnvironment*)
    : BytecodeGeneratorBase(makeUnique<UnlinkedCodeBlockGenerator>(vm, codeBlock), CodeBlock::llintBaselineCalleeSaveSpaceAsVirtualRegisters())
    , m_codeGenerationMode(codeGenerationMode)
    , m_scopeNode(programNode)
    ...
{
    ASSERT_UNUSED(parentScopeTDZVariables, !parentScopeTDZVariables);

    m_codeBlock->setNumParameters(1); // Allocate space for "this"

    emitEnter();

    allocateAndEmitScope();

    emitCheckTraps();

    ...
}
```

Follow into the `bytecodeGenerator->generate` function, it calls `m_scopeNode->emitBytecode` to generate the `unlinked` bytecode and then emits all the `exception handler` for the program, and at last call `m_codeBlock->finalize` to finalize the bytecode.

```c++
// bytecompiler/BytecodeGenerator.cpp: 151
ParserError BytecodeGenerator::generate(unsigned& size)
{
    ...
    
        m_scopeNode->emitBytecode(*this);
			...
			for (auto& handler : m_exceptionHandlersToEmit) {
        Ref<Label> realCatchTarget = newLabel();
        TryData* tryData = handler.tryData;

        OpCatch::emit(this, handler.exceptionRegister, handler.thrownValueRegister);
        realCatchTarget->setLocation(*this, m_lastInstruction.offset());
        if (handler.completionTypeRegister.isValid()) {
            RegisterID completionTypeRegister { handler.completionTypeRegister };
            CompletionType completionType =
                tryData->handlerType == HandlerType::Finally || tryData->handlerType == HandlerType::SynthesizedFinally
                ? CompletionType::Throw
                : CompletionType::Normal;
            emitLoad(&completionTypeRegister, completionType);
        }
        m_codeBlock->addJumpTarget(m_lastInstruction.offset());


        emitJump(tryData->target.get());
        tryData->target = WTFMove(realCatchTarget);
    }

		...
    m_codeBlock->finalize(m_writer.finalize());
```

For `m_scopeNode` is a `ProgramNode`, the corresponding `emitBytecode` is `ProgramNode::emitBytecode`, it inner calls  `emitProgramNodeBytecode` function.

```c++
// bytecompiler/NodesCodegen.cpp: 4777
void ProgramNode::emitBytecode(BytecodeGenerator& generator, RegisterID*)
{
    emitProgramNodeBytecode(generator, *this);
}
```

In `emitProgramNodeBytecode` function, it will first call `generator.emitLoad` to emits a `load` bytecode, which in the `demo` is `mov                dst:loc6, src:Undefined(const0)`, and then calls `scopeNode.emitStatementsBytecode` function to traverse the `AST` tree to generate the `unlinked` bytecode.

```c++
// bytecompiler/NodesCodegen.cpp: 4762
static void emitProgramNodeBytecode(BytecodeGenerator& generator, ScopeNode& scopeNode)
{
    generator.emitDebugHook(WillExecuteProgram, scopeNode.startLine(), scopeNode.startStartOffset(), scopeNode.startLineStartOffset());

    RefPtr<RegisterID> dstRegister = generator.newTemporary();
    generator.emitLoad(dstRegister.get(), jsUndefined());
    generator.emitProfileControlFlow(scopeNode.startStartOffset());
    scopeNode.emitStatementsBytecode(generator, dstRegister.get());

    generator.emitDebugHook(DidExecuteProgram, scopeNode.lastLine(), scopeNode.startOffset(), scopeNode.lineStartOffset());
    generator.emitEnd(dstRegister.get());
}
```

Get into the `ScopeNode::emitStatementsBytecode` function, we can see it calls `emitBytecode` function for the `AST` tree `m_statements`.

```c++
// bytecompiler/NodesCodegen.cpp: 4755
inline void ScopeNode::emitStatementsBytecode(BytecodeGenerator& generator, RegisterID* dst)
{
    if (!m_statements)
        return;
    m_statements->emitBytecode(generator, dst);
}
```

In `SourceElements::emitBytecode` function, it traverses the `AST` tree, and calls `emitNodeInTailPosition` for each `AST` node(`statment`). 

```c++
// bytecompiler/NodesCodegen.cpp: 3804
inline void SourceElements::emitBytecode(BytecodeGenerator& generator, RegisterID* dst)
{
    StatementNode* lastStatementWithCompletionValue = nullptr;
    ...

    for (StatementNode* statement = m_head; statement; statement = statement->next()) {
        if (statement == lastStatementWithCompletionValue)
            generator.emitLoad(dst, jsUndefined());
        generator.emitNodeInTailPosition(dst, statement);
    }
}

				
```

As the code shows, `emitNodeInTailPosition` function will call the corresponding `statement`'s(`opcode`) `emitBytecode` function.

```c++
				// bytecompiler/NodesCodegen.cpp: 475
        void emitNodeInTailPosition(RegisterID* dst, StatementNode* n)
        {
            ...
            n->emitBytecode(*this, dst);
        }
```

The various opcodes are defined in [`BytecodeList.rb`](https://github.com/WebKit/WebKit/blob/main/Source/JavaScriptCore/bytecode/BytecodeList.rb) which at compile time is used to generate `BytecodeStructs.h` which is referenced by the `BytecodeGenerator` to emit the relevant opcodes(`statement`). The structs for the various opcodes also define several helper functions, one of which allows dumping bytecodes to stdout in a human readable format. `BytecodeStructs.h` is typically located under `<build-directory>/Debug/DerivedSources/JavaScriptCore/BytecodeStructs.h`. An example of the `OpAdd` instruction is shown below:

```c++
// DerivedSources/JavaScriptCore/BytecodeStructs.h: 3731
struct OpAdd : public Instruction {
    static constexpr OpcodeID opcodeID = op_add;
    static constexpr size_t length = 6;
    
    


    template<typename BytecodeGenerator>
    static void emit(BytecodeGenerator* gen, VirtualRegister dst, VirtualRegister lhs, VirtualRegister rhs, OperandTypes operandTypes)
    {
        emitWithSmallestSizeRequirement<OpcodeSize::Narrow, BytecodeGenerator>(gen, dst, lhs, rhs, operandTypes);
    }
  
  ...
   template<OpcodeSize __size, bool recordOpcode, typename BytecodeGenerator>
    static bool emitImpl(BytecodeGenerator* gen, VirtualRegister dst, VirtualRegister lhs, VirtualRegister rhs, OperandTypes operandTypes, unsigned __metadataID)
    {
        
        if (__size == OpcodeSize::Wide16)
            gen->alignWideOpcode16();
        else if (__size == OpcodeSize::Wide32)
            gen->alignWideOpcode32();
        if (checkImpl<__size>(gen, dst, lhs, rhs, operandTypes, __metadataID)) {
            if (recordOpcode)
                gen->recordOpcode(opcodeID);
            if (__size == OpcodeSize::Wide16)
                gen->write(Fits<OpcodeID, OpcodeSize::Narrow>::convert(op_wide16));
            else if (__size == OpcodeSize::Wide32)
                gen->write(Fits<OpcodeID, OpcodeSize::Narrow>::convert(op_wide32));
            gen->write(Fits<OpcodeID, OpcodeSize::Narrow>::convert(opcodeID));
            gen->write(Fits<VirtualRegister, __size>::convert(dst));
            gen->write(Fits<VirtualRegister, __size>::convert(lhs));
            gen->write(Fits<VirtualRegister, __size>::convert(rhs));
            gen->write(Fits<OperandTypes, __size>::convert(operandTypes));
            gen->write(Fits<unsigned, __size>::convert(__metadataID));
            return true;
        }
        return false;
    }

public:
    void dump(BytecodeDumperBase* dumper, InstructionStream::Offset __location, int __sizeShiftAmount)
    {
        dumper->printLocationAndOp(__location, &"**add"[2 - __sizeShiftAmount]);
        dumper->dumpOperand("dst", m_dst, true);
        dumper->dumpOperand("lhs", m_lhs, false);
        dumper->dumpOperand("rhs", m_rhs, false);
        dumper->dumpOperand("operandTypes", m_operandTypes, false);
    }
		...
    VirtualRegister m_dst;
    VirtualRegister m_lhs;
    VirtualRegister m_rhs;
    OperandTypes m_operandTypes;
    unsigned m_metadataID;
};
```

Because our demo's first `statement` is `DeclarationStatement`, so it will call `DeclarationStatement::emitBytecode`.  Follow the execution flow, it will call `AssignResolveNode::emitBytecode` function at the end.

```c++
// bytecompiler/NodesCodegen.cpp: 3856
void DeclarationStatement::emitBytecode(BytecodeGenerator& generator, RegisterID*)
{
    ASSERT(m_expr);
    generator.emitNode(m_expr);
}

        // bytecompiler/BytecodeGenerator.h: 520
				RegisterID* emitNode(ExpressionNode* n)
        {
            return emitNode(nullptr, n);
        }
				...
        // bytecompiler/BytecodeGenerator.h: 503
        RegisterID* emitNode(RegisterID* dst, ExpressionNode* n)
        {
            SetForScope<bool> tailPositionPoisoner(m_inTailPosition, false);
            return emitNodeInTailPosition(dst, n);
        }
```

`AssignResolveNode::emitBytecode` function first involkes `emitResolveScope` function to emit `resolve_scope` bytecode, which in our example is `[  10] resolve_scope      dst:loc7, scope:loc4, var:0, resolveType:GlobalProperty, localScopeDepth:0`. And then call `generator.emitNode` function to emit `load` for our value, for the value is `constant 10`, so there is no load. At last it call `emitPutToScope` to emits `put_to_scope` bytecode.

```c++
// bytecompiler/BytecodeGenerator.h: 3573
RegisterID* AssignResolveNode::emitBytecode(BytecodeGenerator& generator, RegisterID* dst)
{
    ...
    RefPtr<RegisterID> scope = generator.emitResolveScope(nullptr, var);
    if (m_assignmentContext == AssignmentContext::AssignmentExpression)
        generator.emitTDZCheckIfNecessary(var, nullptr, scope.get());
    if (dst == generator.ignoredResult())
        dst = nullptr;
    RefPtr<RegisterID> result = generator.emitNode(dst, m_right); // Execute side effects first.
    ...
    if (!isReadOnly) {
        returnResult = generator.emitPutToScope(scope.get(), var, result.get(), generator.ecmaMode().isStrict() ? ThrowIfNotFound : DoNotThrowIfNotFound, initializationModeForAssignmentContext(m_assignmentContext));
        generator.emitProfileType(result.get(), var, divotStart(), divotEnd());
    }

    ...
    return returnResult;
}
```

I want to trace more to figure out how the bytecode is generated, so i take `emitResolveScope` as a example to see how the `unlinked` bytecode `resolve_scope` is generated. Get into the function, we can see it will call  `OpResolveScope::emit` function according to `variable.offset().kind()`.

```c++
// bytecompiler/BytecodeGenerator.cpp: 2465
RegisterID* BytecodeGenerator::emitResolveScope(RegisterID* dst, const Variable& variable)
{
    switch (variable.offset().kind()) {
    ...
    case VarKind::Invalid:
        // Indicates non-local resolution.
        
        dst = tempDestination(dst);
        OpResolveScope::emit(this, kill(dst), scopeRegister(), addConstant(variable.ident()), resolveType(), localScopeDepth());
        return dst;
    }
    
    RELEASE_ASSERT_NOT_REACHED();
    return nullptr;
}
```

As said before, opcodes are defined in [`BytecodeList.rb`](https://github.com/WebKit/WebKit/blob/main/Source/JavaScriptCore/bytecode/BytecodeList.rb), and the generators for the opcodes are generated at compile time which finnally are stored in  `<build-directory>/Debug/DerivedSources/JavaScriptCore/BytecodeStructs.h`. So follow the `OpResolveScope::emit` will trace into the `OpResolveScope` related generator. The generator is shown as below, as we can see, it will finally call  `gen->write` to write the specific byte to the bytecode array.

```c++
// DerivedSources/JavaScriptCore/BytecodeStructs.h: 12331
struct OpResolveScope : public Instruction {
    static constexpr OpcodeID opcodeID = op_resolve_scope;
    static constexpr size_t length = 7;
    
    


    template<typename BytecodeGenerator>
    static void emit(BytecodeGenerator* gen, VirtualRegister dst, VirtualRegister scope, unsigned var, ResolveType resolveType, unsigned localScopeDepth)
    {
        emitWithSmallestSizeRequirement<OpcodeSize::Narrow, BytecodeGenerator>(gen, dst, scope, var, resolveType, localScopeDepth);
    }
  ...
  template<OpcodeSize __size, typename BytecodeGenerator>
    static void emitWithSmallestSizeRequirement(BytecodeGenerator* gen, VirtualRegister dst, VirtualRegister scope, unsigned var, ResolveType resolveType, unsigned localScopeDepth)
    {
        
        auto __metadataID = gen->addMetadataFor(opcodeID);
        if (static_cast<unsigned>(__size) <= static_cast<unsigned>(OpcodeSize::Narrow)) {
            if (emit<OpcodeSize::Narrow, BytecodeGenerator, NoAssert, true>(gen, dst, scope, var, resolveType, localScopeDepth, __metadataID))
                return;
        }
        ...
    }
  	...
		template<OpcodeSize __size, bool recordOpcode, typename BytecodeGenerator>
    static bool emitImpl(BytecodeGenerator* gen, VirtualRegister dst, VirtualRegister scope, unsigned var, ResolveType resolveType, unsigned localScopeDepth, unsigned __metadataID)
    {
        
        if (__size == OpcodeSize::Wide16)
            gen->alignWideOpcode16();
        else if (__size == OpcodeSize::Wide32)
            gen->alignWideOpcode32();
        if (checkImpl<__size>(gen, dst, scope, var, resolveType, localScopeDepth, __metadataID)) {
            if (recordOpcode)
                gen->recordOpcode(opcodeID);
            if (__size == OpcodeSize::Wide16)
                gen->write(Fits<OpcodeID, OpcodeSize::Narrow>::convert(op_wide16));
            else if (__size == OpcodeSize::Wide32)
                gen->write(Fits<OpcodeID, OpcodeSize::Narrow>::convert(op_wide32));
            gen->write(Fits<OpcodeID, OpcodeSize::Narrow>::convert(opcodeID));
            gen->write(Fits<VirtualRegister, __size>::convert(dst));
            gen->write(Fits<VirtualRegister, __size>::convert(scope));
            gen->write(Fits<unsigned, __size>::convert(var));
            gen->write(Fits<ResolveType, __size>::convert(resolveType));
            gen->write(Fits<unsigned, __size>::convert(localScopeDepth));
            gen->write(Fits<unsigned, __size>::convert(__metadataID));
            return true;
        }
        return false;
    }
  ...
  public:
    void dump(BytecodeDumperBase* dumper, InstructionStream::Offset __location, int __sizeShiftAmount)
    {
        dumper->printLocationAndOp(__location, &"**resolve_scope"[2 - __sizeShiftAmount]);
        dumper->dumpOperand("dst", m_dst, true);
        dumper->dumpOperand("scope", m_scope, false);
        dumper->dumpOperand("var", m_var, false);
        dumper->dumpOperand("resolveType", m_resolveType, false);
        dumper->dumpOperand("localScopeDepth", m_localScopeDepth, false);
    }
```

Right now we have figured out the way that `BytecodeGenerator::generate` function traverses the `AST` tree and generate the `bytecode` stream. After all the `bytecode` is generated, which is stored in `m_writer`, it will call `m_codeBlock->finalize(m_writer.finalize())` to finalize the final `unlinked` bytecode.

Let's get into `finalize` function, it will first copy the `instructions` to `m_instructions`, and then allocate `ArithProfile` for the bytecode, and then call `m_metadata->finalize` to allocate `metadata` for bytecode, the rest is the other assignment, such as `m_jumpTargets`, `m_identifiers` and `m_functionExprs`.

```c++
// bytecode/UnlinkedCodeBlockGenerator.cpp: 116    
void UnlinkedCodeBlockGenerator::finalize(std::unique_ptr<InstructionStream> instructions)
{
    ASSERT(instructions);
    {
        Locker locker { m_codeBlock->cellLock() };
        m_codeBlock->m_instructions = WTFMove(instructions);
        m_codeBlock->allocateSharedProfiles(m_numBinaryArithProfiles, m_numUnaryArithProfiles);
        m_codeBlock->m_metadata->finalize();

        m_codeBlock->m_jumpTargets = WTFMove(m_jumpTargets);
        m_codeBlock->m_identifiers = WTFMove(m_identifiers);
        m_codeBlock->m_constantRegisters = WTFMove(m_constantRegisters);
        m_codeBlock->m_constantsSourceCodeRepresentation = WTFMove(m_constantsSourceCodeRepresentation);
        m_codeBlock->m_functionDecls = WTFMove(m_functionDecls);
        m_codeBlock->m_functionExprs = WTFMove(m_functionExprs);
        m_codeBlock->m_expressionInfo = WTFMove(m_expressionInfo);
        m_codeBlock->m_outOfLineJumpTargets = WTFMove(m_outOfLineJumpTargets);

        ...
}

// bytecode/UnlinkedMetadataTable.cpp: 39  
void UnlinkedMetadataTable::finalize()
{
    ASSERT(!m_isFinalized);
    m_isFinalized = true;
    if (!m_hasMetadata) {
        MetadataTableMalloc::free(m_rawBuffer);
        m_rawBuffer = nullptr;
        return;
    }

    unsigned offset = s_offset16TableSize;
    {
        Offset32* buffer = preprocessBuffer();
        for (unsigned i = 0; i < s_offsetTableEntries - 1; i++) {
            unsigned numberOfEntries = buffer[i];
            if (!numberOfEntries) {
                buffer[i] = offset;
                continue;
            }
            buffer[i] = offset; // We align when we access this.
            unsigned alignment = metadataAlignment(static_cast<OpcodeID>(i));
            offset = roundUpToMultipleOf(alignment, offset);
            ASSERT(alignment <= s_maxMetadataAlignment);
            offset += numberOfEntries * metadataSize(static_cast<OpcodeID>(i));
        }
        buffer[s_offsetTableEntries - 1] = offset;
        m_is32Bit = offset > UINT16_MAX;
    }

    if (m_is32Bit) {
        ...
    } else {
        Offset32* oldBuffer = bitwise_cast<Offset32*>(m_rawBuffer + sizeof(LinkingData));
        Offset16* buffer = bitwise_cast<Offset16*>(m_rawBuffer + sizeof(LinkingData));
        for (unsigned i = 0; i < s_offsetTableEntries; i++)
            buffer[i] = oldBuffer[i];
        m_rawBuffer = static_cast<uint8_t*>(MetadataTableMalloc::realloc(m_rawBuffer, s_offset16TableSize + sizeof(LinkingData)));
    }
}
```

## Generate linked bytecode

Now that we have finished analysis of `initializeGlobalProperties` function and `unlinked` bytecode is generated, we can go back  `executeProgram` to move to the next step.  

```c++
// interpreter/Interpreter.cpp: 709
JSValue Interpreter::executeProgram(const SourceCode& source, JSGlobalObject*, JSObject* thisObj)
{
    ...
    
    JSObject* error = program->initializeGlobalProperties(vm, globalObject, scope);
    ...

    ProgramCodeBlock* codeBlock;
    {
        CodeBlock* tempCodeBlock;
        program->prepareForExecution<ProgramExecutable>(vm, nullptr, scope, CodeForCall, tempCodeBlock);
        RETURN_IF_EXCEPTION(throwScope, checkedReturn(throwScope.exception()));

        codeBlock = jsCast<ProgramCodeBlock*>(tempCodeBlock);
        ASSERT(codeBlock && codeBlock->numParameters() == 1); // 1 parameter for 'this'.
    }

    RefPtr<JITCode> jitCode;
    ProtoCallFrame protoCallFrame;
    {
        DisallowGC disallowGC; // Ensure no GC happens. GC can replace CodeBlock in Executable.
        jitCode = program->generatedJITCode();
        protoCallFrame.init(codeBlock, globalObject, globalCallee, thisObj, 1);
    }

    // Execute the code:
    throwScope.release();
    ASSERT(jitCode == program->generatedJITCode().ptr());
    JSValue result = jitCode->execute(&vm, &protoCallFrame);
    return checkedReturn(result);
}
```

As we can see, the `executeProgram` function calls `program->prepareForExecution` to link the `unlinked` bytecode to `linked` bytecode. 

Let's start analysis `prepareForExecution` function. It inner calls `prepareForExecutionImpl`.

```c++
// bytecode/CodeBlock.h:1002
template <typename ExecutableType>
void ScriptExecutable::prepareForExecution(VM& vm, JSFunction* function, JSScope* scope, CodeSpecializationKind kind, CodeBlock*& resultCodeBlock)
{
    ...
    prepareForExecutionImpl(vm, function, scope, kind, resultCodeBlock);
}
```

In `prepareForExecutionImpl` function, it perform 2 actions:

* calls `newCodeBlockFor` to link the `unlinked` bytecode to `linked` bytecode, and create `codeBlock` object.
* calls `setupLLInt` function to set up the entry point to the program, which `LLInt` will start interpreter from.

```c++
// runtime/ScriptExecutable.cpp: 379
void ScriptExecutable::prepareForExecutionImpl(VM& vm, JSFunction* function, JSScope* scope, CodeSpecializationKind kind, CodeBlock*& resultCodeBlock)
{
    ...

    CodeBlock* codeBlock = newCodeBlockFor(kind, function, scope);
    ...
    resultCodeBlock = codeBlock;

    if (Options::validateBytecode())
        codeBlock->validate();

    bool installedUnlinkedBaselineCode = false;
#if ENABLE(JIT)
    if (RefPtr<BaselineJITCode> baselineRef = codeBlock->unlinkedCodeBlock()->m_unlinkedBaselineCode) {
        codeBlock->setupWithUnlinkedBaselineCode(baselineRef.releaseNonNull());
        installedUnlinkedBaselineCode = true;
    }
#endif
    if (!installedUnlinkedBaselineCode) {
        if (Options::useLLInt())
            setupLLInt(codeBlock);
        else
            setupJIT(vm, codeBlock);
    }

    installCode(vm, codeBlock, codeBlock->codeType(), codeBlock->specializationKind());
}
```

Let's first go into the `newCodeBlockFor` function to see how `linked` bytecode is generated. It will call `ProgramCodeBlock::create` to perform the generation, and the `create` function will call `instance->finishCreation` to do the action.

```c++
// runtime/ScriptExecutable.cpp: 249
CodeBlock* ScriptExecutable::newCodeBlockFor(CodeSpecializationKind kind, JSFunction* function, JSScope* scope)
{
    ...

    if (classInfo(vm) == ProgramExecutable::info()) {
        ProgramExecutable* executable = jsCast<ProgramExecutable*>(this);
        RELEASE_ASSERT(kind == CodeForCall);
        RELEASE_ASSERT(!executable->m_programCodeBlock);
        RELEASE_ASSERT(!function);
        RELEASE_AND_RETURN(throwScope, ProgramCodeBlock::create(vm, executable, executable->m_unlinkedProgramCodeBlock.get(), scope));
    }

    ...

}
		// bytecode/ProgramCodeBlock.h: 56
		static ProgramCodeBlock* create(VM& vm, ProgramExecutable* ownerExecutable, UnlinkedProgramCodeBlock* unlinkedCodeBlock, JSScope* scope)
    {
        ProgramCodeBlock* instance = new (NotNull, allocateCell<ProgramCodeBlock>(vm))
            ProgramCodeBlock(vm, vm.programCodeBlockStructure.get(), ownerExecutable, unlinkedCodeBlock, scope);
        if (!instance->finishCreation(vm, ownerExecutable, unlinkedCodeBlock, scope))
            return nullptr;
        return instance;
    }
```

Follow into the `instance->finishCreation` function, we can see from the comment that this function is used to generate linked bytecode from unlinked bytecode. It will traverse every `unlinked` bytecode and call `LINK` to link it the the `linked` bytecde, as well as initialize `metedata`.

```c++
// bytecode/CodeBlock.cpp: 355
// The main purpose of this function is to generate linked bytecode from unlinked bytecode. The process
// of linking is taking an abstract representation of bytecode and tying it to a GlobalObject and scope
// chain. For example, this process allows us to cache the depth of lexical environment reads that reach
// outside of this CodeBlock's compilation unit. It also allows us to generate particular constants that
// we can't generate during unlinked bytecode generation. This process is not allowed to generate control
// flow or introduce new locals. The reason for this is we rely on liveness analysis to be the same for
// all the CodeBlocks of an UnlinkedCodeBlock. We rely on this fact by caching the liveness analysis
// inside UnlinkedCodeBlock. Also, Baseline JIT code is shared between all CodeBlocks of an UnlinkedCodeBlock,
// so the bytecode must remain the same between CodeBlocks sharing an UnlinkedCodeBlock.
bool CodeBlock::finishCreation(VM& vm, ScriptExecutable* ownerExecutable, UnlinkedCodeBlock* unlinkedCodeBlock,
    JSScope* scope)
{
    ...

#define LINK_FIELD(__field) \
    WTF_LAZY_JOIN(link_, __field)(instruction, bytecode, metadata);

#define INITIALIZE_METADATA(__op) \
    auto bytecode = instruction->as<__op>(); \
    auto& metadata = bytecode.metadata(this); \
    new (&metadata) __op::Metadata { bytecode }; \

#define LINK_IMPL(...) \
        INITIALIZE_METADATA(WTF_LAZY_FIRST(__VA_ARGS__)) \
        WTF_LAZY_HAS_REST(__VA_ARGS__)({ \
            WTF_LAZY_FOR_EACH_TERM(LINK_FIELD,  WTF_LAZY_REST_(__VA_ARGS__)) \
        }) \

#define CASE(__op) case __op::opcodeID

#define LINK(...) \
    CASE(WTF_LAZY_FIRST(__VA_ARGS__)): { \
        LINK_IMPL(__VA_ARGS__) \
        break; \
    }
    ...
    const InstructionStream& instructionStream = instructions();
    for (const auto& instruction : instructionStream) {
        OpcodeID opcodeID = instruction->opcodeID();
        m_bytecodeCost += opcodeLengths[opcodeID];
        switch (opcodeID) {
        LINK(OpGetByVal, profile)
        LINK(OpGetPrivateName, profile)

        LINK(OpGetByIdWithThis, profile)
        LINK(OpTryGetById, profile)
        LINK(OpGetByIdDirect, profile)
```

When finished the generation of `linked` bytecode, `jsc` goes back to `prepareForExecutionImpl` function, and `prepareForExecutionImpl` then calls `setupLLInt` function which eventually calls `setProgramEntrypoint` to set up the entry point to the program for the `LLInt` to being executing from.

```c++
// runtime/ScriptExecutable.cpp: 362
static void setupLLInt(CodeBlock* codeBlock)
{
    LLInt::setEntrypoint(codeBlock);
}

// llint/LLIntEntrypoint.cpp: 229
void setEntrypoint(CodeBlock* codeBlock)
{
    switch (codeBlock->codeType()) {
    case GlobalCode:
        setProgramEntrypoint(codeBlock);
        return;
    ...
        return;
}

// llint/LLIntEntrypoint.cpp: 139
static void setProgramEntrypoint(CodeBlock* codeBlock)
{
#if ENABLE(JIT)
    if (Options::useJIT()) {
        static NativeJITCode* jitCode;
        static std::once_flag onceKey;
        std::call_once(onceKey, [&] {
            MacroAssemblerCodeRef<JSEntryPtrTag> codeRef = programEntryThunk();
            jitCode = new NativeJITCode(codeRef, JITType::InterpreterThunk, Intrinsic::NoIntrinsic, JITCode::ShareAttribute::Shared);
        });
        codeBlock->setJITCode(*jitCode);
        return;
    }
...
}
```

Right now, we get the `linked` bytecode and also set up the entry point for the LLInt, we can continue to move to the next step.

## Ready to execute bytecode

As we can see from the code, when `prepareForExecution` function finishes the generation of `linked` bytecode, the `executeProgram` function will calls `generatedJITCode` and `protoCallFrame.init` to make the final preparations for running the interpreter.

```c++
// interpreter/Interpreter.cpp: 709
JSValue Interpreter::executeProgram(const SourceCode& source, JSGlobalObject*, JSObject* thisObj)
{
    ...
    
    JSObject* error = program->initializeGlobalProperties(vm, globalObject, scope);
    ...
        program->prepareForExecution<ProgramExecutable>(vm, nullptr, scope, CodeForCall, tempCodeBlock);
        ...

    RefPtr<JITCode> jitCode;
    ProtoCallFrame protoCallFrame;
    {
        DisallowGC disallowGC; // Ensure no GC happens. GC can replace CodeBlock in Executable.
        jitCode = program->generatedJITCode();
        protoCallFrame.init(codeBlock, globalObject, globalCallee, thisObj, 1);
    }

    // Execute the code:
    throwScope.release();
    ASSERT(jitCode == program->generatedJITCode().ptr());
    JSValue result = jitCode->execute(&vm, &protoCallFrame);
    return checkedReturn(result);
}
```

`generatedJITCode` returns a reference pointer to the interpreted code, which is used to start running the interpreter.

```c++
    // runtime/ProgramExecutable.h: 62
		Ref<JITCode> generatedJITCode()
    {
        return generatedJITCodeForCall();
    }
		
		// runtime/ProgramExecutable.h: 113
    Ref<JITCode> generatedJITCodeForCall() const
    {
        ASSERT(m_jitCodeForCall);
        return *m_jitCodeForCall;
    }
```

`protoCallFrame.init` initialize a `ProtoCallFrame` with the generated `codeBlock`.

```c++
// interpreter/ProtoCallFrameInlined.h: 33
inline void ProtoCallFrame::init(CodeBlock* codeBlock, JSGlobalObject* globalObject, JSObject* callee, JSValue thisValue, int argCountIncludingThis, JSValue* otherArgs)
{
    this->args = otherArgs;
    this->setCodeBlock(codeBlock);
    this->setCallee(callee);
    this->setGlobalObject(globalObject);
    this->setArgumentCountIncludingThis(argCountIncludingThis);
    if (codeBlock && static_cast<unsigned>(argCountIncludingThis) < codeBlock->numParameters())
        this->hasArityMismatch = true;
    else
        this->hasArityMismatch = false;

    // Round up argCountIncludingThis to keep the stack frame size aligned.
    size_t paddedArgsCount = roundArgumentCountToAlignFrame(argCountIncludingThis);
    this->setPaddedArgCount(paddedArgsCount);
    this->clearCurrentVPC();
    this->setThisValue(thisValue);
}
```

Now that everything is ready, it will call `JSValue result = jitCode->execute(&vm, &protoCallFrame);` to `execute` the `linked` bytecode, but this should be explained in the next post.

## Conclusion

In this post, we have finished the analysis of how the jsc compile js source to the bytecode. 

Specifially, it first set up the runtime, and then parse the source to `AST` tree, and generate the `unlinked` bytecode with `AST` tree, and then links the `unlinked` bytecode to `linked` bytecode and finally sets up the entry point for running. Now all the things are ready, we can start to interpreter the bytecode.

I learned a lot from this process, most importantly, it helps me to get a deeper understanding of the jsc code. In the next part, i'll try to explain the way that jsc interpreter the bytecode.

## Reference

* [JavaScriptCore Internals Part I: Tracing JavaScript Source to Bytecode](https://zon8.re/posts/jsc-internals-part1-tracing-js-source-to-bytecode/)
* [A New Bytecode Format for JavaScriptCore](https://webkit.org/blog/9329/a-new-bytecode-format-for-javascriptcore/)
