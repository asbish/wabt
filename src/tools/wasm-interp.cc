/*
 * Copyright 2016 WebAssembly Community Group participants
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "src/binary-reader.h"
#include "src/error-formatter.h"
#include "src/feature.h"
#include "src/interp2/interp2.h"
#include "src/interp2/read-module.h"
#include "src/option-parser.h"
#include "src/stream.h"

using namespace wabt;
using namespace wabt::interp2;

namespace {

int s_verbose;
const char* s_infile;
Thread::Options s_thread_options;
Stream* s_trace_stream;
bool s_run_all_exports;
bool s_host_print;
bool s_dummy_import_func;
Features s_features;

std::unique_ptr<FileStream> s_log_stream;
std::unique_ptr<FileStream> s_stdout_stream;

Store s_store;

}  // namespace

static const char s_description[] =
    R"(  read a file in the wasm binary format, and run in it a stack-based
  interpreter.

examples:
  # parse binary file test.wasm, and type-check it
  $ wasm-interp test.wasm

  # parse test.wasm and run all its exported functions
  $ wasm-interp test.wasm --run-all-exports

  # parse test.wasm, run the exported functions and trace the output
  $ wasm-interp test.wasm --run-all-exports --trace

  # parse test.wasm and run all its exported functions, setting the
  # value stack size to 100 elements
  $ wasm-interp test.wasm -V 100 --run-all-exports
)";

static void ParseOptions(int argc, char** argv) {
  OptionParser parser("wasm-interp", s_description);

  parser.AddOption('v', "verbose", "Use multiple times for more info", []() {
    s_verbose++;
    s_log_stream = FileStream::CreateStdout();
  });
  s_features.AddOptions(&parser);
  parser.AddOption('V', "value-stack-size", "SIZE",
                   "Size in elements of the value stack",
                   [](const std::string& argument) {
                     // TODO(binji): validate.
                     s_thread_options.value_stack_size = atoi(argument.c_str());
                   });
  parser.AddOption('C', "call-stack-size", "SIZE",
                   "Size in elements of the call stack",
                   [](const std::string& argument) {
                     // TODO(binji): validate.
                     s_thread_options.call_stack_size = atoi(argument.c_str());
                   });
  parser.AddOption('t', "trace", "Trace execution",
                   []() { s_trace_stream = s_stdout_stream.get(); });
  parser.AddOption(
      "run-all-exports",
      "Run all the exported functions, in order. Useful for testing",
      []() { s_run_all_exports = true; });
  parser.AddOption("host-print",
                   "Include an importable function named \"host.print\" for "
                   "printing to stdout",
                   []() { s_host_print = true; });
  parser.AddOption(
      "dummy-import-func",
      "Provide a dummy implementation of all imported functions. The function "
      "will log the call and return an appropriate zero value.",
      []() { s_dummy_import_func = true; });

  parser.AddArgument("filename", OptionParser::ArgumentCount::One,
                     [](const char* argument) { s_infile = argument; });
  parser.Parse(argc, argv);
}

void WriteTrap(Stream* stream, const char* desc, const Trap::Ptr& trap) {
  stream->Writef("%s: %s\n", desc, trap->message().c_str());
}

std::string TypedValueToString(ValueType type, const Value& val) {
  switch (type) {
    case Type::I32:
      return StringPrintf("i32:%u", val.Get<s32>());

    case Type::I64:
      return StringPrintf("i64:%" PRIu64, val.Get<s64>());

    case Type::F32:
      return StringPrintf("f32:%f", val.Get<f32>());

    case Type::F64:
      return StringPrintf("f64:%f", val.Get<f64>());

    case Type::V128: {
      v128 simd = val.Get<v128>();
      return StringPrintf("v128 i32x4:0x%08x 0x%08x 0x%08x 0x%08x", simd.v[0],
                          simd.v[1], simd.v[2], simd.v[3]);
    }

    case Type::Nullref:
      return StringPrintf("nullref");

    case Type::Hostref:
      return StringPrintf("hostref:%" PRIzd, val.Get<Ref>().index);

    case Type::Funcref:
      return StringPrintf("funcref:%" PRIzd, val.Get<Ref>().index);

    case Type::Exnref:
      return StringPrintf("exnref:%" PRIzd, val.Get<Ref>().index);

    case Type::Func:
    case Type::Void:
    case Type::Any:
    case Type::Anyref:
    case Type::I8:
    case Type::I8U:
    case Type::I16:
    case Type::I16U:
    case Type::I32U:
      // These types are not concrete types and should never exist as a value
      WABT_UNREACHABLE;
  }
  WABT_UNREACHABLE;
}

void WriteValue(Stream* stream, ValueType type, const Value& value) {
  std::string s = TypedValueToString(type, value);
  stream->WriteData(s.data(), s.size());
}

void WriteValues(Stream* stream,
                 const ValueTypes& types,
                 const Values& values) {
  for (size_t i = 0; i < values.size(); ++i) {
    WriteValue(stream, types[i], values[i]);
    if (i != values.size() - 1) {
      stream->Writef(", ");
    }
  }
}

void WriteCall(Stream* stream,
               string_view name,
               const FuncType& func_type,
               const Values& params,
               const Values& results,
               const Trap::Ptr& trap) {
  stream->Writef(PRIstringview "(", WABT_PRINTF_STRING_VIEW_ARG(name));
  WriteValues(stream, func_type.params, params);
  stream->Writef(") =>");
  if (!trap) {
    if (!results.empty()) {
      stream->Writef(" ");
      WriteValues(stream, func_type.results, results);
    }
    stream->Writef("\n");
  } else {
    WriteTrap(stream, " error", trap);
  }
}

Result RunAllExports(const Instance::Ptr& instance, Errors* errors) {
  Result result = Result::Ok;

  auto module = s_store.UnsafeGet<Module>(instance->module());
  auto&& module_desc = module->desc();

  for (auto&& export_ : module_desc.exports) {
    if (export_.type.type->kind != ExternalKind::Func) {
      continue;
    }
    auto* func_type = cast<FuncType>(export_.type.type.get());
    if (func_type->params.empty()) {
      if (s_trace_stream) {
        s_trace_stream->Writef(">>> running export \"%s\"\n",
                               export_.type.name.c_str());
      }
      auto func = s_store.UnsafeGet<Func>(instance->funcs()[export_.index]);
      Values params;
      Values results;
      Trap::Ptr trap;
      result |= func->Call(s_store, params, results, &trap, s_trace_stream);
      WriteCall(s_stdout_stream.get(), export_.type.name, *func_type, params,
                results, trap);
    }
  }

  return result;
}

Result ReadAndInstantiateModule(const char* module_filename,
                                Errors* errors,
                                Instance::Ptr* out_instance) {
  auto* stream = s_stdout_stream.get();
  std::vector<uint8_t> file_data;
  CHECK_RESULT(ReadFile(module_filename, &file_data));

  ModuleDesc module_desc;
  const bool kReadDebugNames = true;
  const bool kStopOnFirstError = true;
  const bool kFailOnCustomSectionError = true;
  ReadBinaryOptions options(s_features, s_log_stream.get(), kReadDebugNames,
                            kStopOnFirstError, kFailOnCustomSectionError);
  CHECK_RESULT(ReadModule(file_data.data(), file_data.size(), options, errors,
                          &module_desc));

  if (s_verbose) {
    module_desc.istream.Disassemble(stream);
  }

  auto module = Module::New(s_store, module_desc);

  RefVec imports;
  for (auto&& import : module_desc.imports) {
    if (import.type.type->kind == ExternKind::Func &&
        ((s_host_print && import.type.module == "host" &&
          import.type.name == "print") ||
         s_dummy_import_func)) {
      auto func_type = *cast<FuncType>(import.type.type.get());
      auto import_name = StringPrintf("%s.%s", import.type.module.c_str(),
                                      import.type.name.c_str());

      auto host_func =
          HostFunc::New(s_store, func_type,
                        [=](const Values& params, Values& results,
                            Trap::Ptr* trap) -> Result {
                          printf("called host ");
                          WriteCall(stream, import_name, func_type, params,
                                    results, *trap);
                          return Result::Ok;
                        });
      imports.push_back(host_func.ref());
      continue;
    }

    // By default, just push an null reference. This won't resolve, and
    // instantiation will fail.
    imports.push_back(Ref::Null);
  }

  RefPtr<Trap> trap;
  *out_instance = Instance::Instantiate(s_store, module.ref(), imports, &trap);
  if (!*out_instance) {
    WriteTrap(stream, "error initializing module", trap);
    return Result::Error;
  }

  return Result::Ok;
}

static Result ReadAndRunModule(const char* module_filename) {
  Errors errors;
  Instance::Ptr instance;
  Result result = ReadAndInstantiateModule(module_filename, &errors, &instance);
  if (Succeeded(result) && s_run_all_exports) {
    RunAllExports(instance, &errors);
  }
  FormatErrorsToFile(errors, Location::Type::Binary);
  return result;
}

int ProgramMain(int argc, char** argv) {
  InitStdio();
  s_stdout_stream = FileStream::CreateStdout();

  ParseOptions(argc, argv);

  Result result = ReadAndRunModule(s_infile);
  return result != Result::Ok;
}

int main(int argc, char** argv) {
  WABT_TRY
  return ProgramMain(argc, argv);
  WABT_CATCH_BAD_ALLOC_AND_EXIT
}
