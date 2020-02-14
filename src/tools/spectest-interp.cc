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
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "src/binary-reader.h"
#include "src/cast.h"
#include "src/common.h"
#include "src/error-formatter.h"
#include "src/feature.h"
#include "src/interp2/interp2-util.h"
#include "src/interp2/interp2.h"
#include "src/interp2/read-module.h"
#include "src/literal.h"
#include "src/option-parser.h"
#include "src/resolve-names.h"
#include "src/stream.h"
#include "src/validator.h"
#include "src/wast-lexer.h"
#include "src/wast-parser.h"

using namespace wabt;
using namespace wabt::interp2;

static int s_verbose;
static const char* s_infile;
static Thread::Options s_thread_options;
static Stream* s_trace_stream;
static Features s_features;

static std::unique_ptr<FileStream> s_log_stream;
static std::unique_ptr<FileStream> s_stdout_stream;

enum class RunVerbosity {
  Quiet = 0,
  Verbose = 1,
};

static const char s_description[] =
    R"(  read a Spectest JSON file, and run its tests in the interpreter.

examples:
  # parse test.json and run the spec tests
  $ spectest-interp test.json
)";

static void ParseOptions(int argc, char** argv) {
  OptionParser parser("spectest-interp", s_description);

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

  parser.AddArgument("filename", OptionParser::ArgumentCount::One,
                     [](const char* argument) { s_infile = argument; });
  parser.Parse(argc, argv);
}

namespace spectest {

class Command;
typedef std::unique_ptr<Command> CommandPtr;
typedef std::vector<CommandPtr> CommandPtrVector;

class Script {
 public:
  std::string filename;
  CommandPtrVector commands;
};

class Command {
 public:
  WABT_DISALLOW_COPY_AND_ASSIGN(Command);
  Command() = delete;
  virtual ~Command() = default;

  CommandType type;
  uint32_t line = 0;

 protected:
  explicit Command(CommandType type) : type(type) {}
};

template <CommandType TypeEnum>
class CommandMixin : public Command {
 public:
  static bool classof(const Command* cmd) { return cmd->type == TypeEnum; }
  CommandMixin() : Command(TypeEnum) {}
};

enum class ModuleType {
  Text,
  Binary,
};

class ModuleCommand : public CommandMixin<CommandType::Module> {
 public:
  ModuleType module = ModuleType::Binary;
  std::string filename;
  std::string name;
};

class Action {
 public:
  ActionType type = ActionType::Invoke;
  std::string module_name;
  std::string field_name;
  Values args;
};

template <CommandType TypeEnum>
class ActionCommandBase : public CommandMixin<TypeEnum> {
 public:
  Action action;
};

typedef ActionCommandBase<CommandType::Action> ActionCommand;

class RegisterCommand : public CommandMixin<CommandType::Register> {
 public:
  std::string as;
  std::string name;
};

struct ExpectedValue {
  bool is_expected_nan;
  Value value;
  ExpectedNan expectedNan;
};

class AssertReturnCommand : public CommandMixin<CommandType::AssertReturn> {
 public:
  Action action;
  std::vector<ExpectedValue> expected;
};

template <CommandType TypeEnum>
class AssertTrapCommandBase : public CommandMixin<TypeEnum> {
 public:
  Action action;
  std::string text;
};

typedef AssertTrapCommandBase<CommandType::AssertTrap> AssertTrapCommand;
typedef AssertTrapCommandBase<CommandType::AssertExhaustion>
    AssertExhaustionCommand;

template <CommandType TypeEnum>
class AssertModuleCommand : public CommandMixin<TypeEnum> {
 public:
  ModuleType type = ModuleType::Binary;
  std::string filename;
  std::string text;
};

typedef AssertModuleCommand<CommandType::AssertMalformed>
    AssertMalformedCommand;
typedef AssertModuleCommand<CommandType::AssertInvalid> AssertInvalidCommand;
typedef AssertModuleCommand<CommandType::AssertUnlinkable>
    AssertUnlinkableCommand;
typedef AssertModuleCommand<CommandType::AssertUninstantiable>
    AssertUninstantiableCommand;

// An extremely simple JSON parser that only knows how to parse the expected
// format from wat2wasm.
class JSONParser {
 public:
  JSONParser() {}

  Result ReadFile(string_view spec_json_filename);
  Result ParseScript(Script* out_script);

 private:
  void WABT_PRINTF_FORMAT(2, 3) PrintError(const char* format, ...);

  void PutbackChar();
  int ReadChar();
  void SkipWhitespace();
  bool Match(const char* s);
  Result Expect(const char* s);
  Result ExpectKey(const char* key);
  Result ParseUint32(uint32_t* out_int);
  Result ParseString(std::string* out_string);
  Result ParseKeyStringValue(const char* key, std::string* out_string);
  Result ParseOptNameStringValue(std::string* out_string);
  Result ParseLine(uint32_t* out_line_number);
  Result ParseTypeObject(Type* out_type);
  Result ParseTypeVector(TypeVector* out_types);
  Result ParseConst(Value* out_value);
  Result ParseConstValue(Value* out_value,
                               string_view type_str,
                               string_view value_str);
  Result ParseConstVector(Values* out_values);
  Result ParseExpectedValue(ExpectedValue* out_value);
  Result ParseExpectedValues(std::vector<ExpectedValue>* out_values);
  Result ParseAction(Action* out_action);
  Result ParseActionResult();
  Result ParseModuleType(ModuleType* out_type);

  std::string CreateModulePath(string_view filename);
  Result ParseFilename(std::string* out_filename);
  Result ParseCommand(CommandPtr* out_command);

  // Parsing info.
  std::vector<uint8_t> json_data_;
  size_t json_offset_ = 0;
  Location loc_;
  Location prev_loc_;
  bool has_prev_loc_ = false;
};

#define EXPECT(x) CHECK_RESULT(Expect(x))
#define EXPECT_KEY(x) CHECK_RESULT(ExpectKey(x))
#define PARSE_KEY_STRING_VALUE(key, value) \
  CHECK_RESULT(ParseKeyStringValue(key, value))

Result JSONParser::ReadFile(string_view spec_json_filename) {
  loc_.filename = spec_json_filename;
  loc_.line = 1;
  loc_.first_column = 1;

  return wabt::ReadFile(spec_json_filename, &json_data_);
}

void JSONParser::PrintError(const char* format, ...) {
  WABT_SNPRINTF_ALLOCA(buffer, length, format);
  fprintf(stderr, "%s:%d:%d: %s\n", loc_.filename.to_string().c_str(),
          loc_.line, loc_.first_column, buffer);
}

void JSONParser::PutbackChar() {
  assert(has_prev_loc_);
  json_offset_--;
  loc_ = prev_loc_;
  has_prev_loc_ = false;
}

int JSONParser::ReadChar() {
  if (json_offset_ >= json_data_.size()) {
    return -1;
  }
  prev_loc_ = loc_;
  char c = json_data_[json_offset_++];
  if (c == '\n') {
    loc_.line++;
    loc_.first_column = 1;
  } else {
    loc_.first_column++;
  }
  has_prev_loc_ = true;
  return c;
}

void JSONParser::SkipWhitespace() {
  while (1) {
    switch (ReadChar()) {
      case -1:
        return;

      case ' ':
      case '\t':
      case '\n':
      case '\r':
        break;

      default:
        PutbackChar();
        return;
    }
  }
}

bool JSONParser::Match(const char* s) {
  SkipWhitespace();
  Location start_loc = loc_;
  size_t start_offset = json_offset_;
  while (*s && *s == ReadChar())
    s++;

  if (*s == 0) {
    return true;
  } else {
    json_offset_ = start_offset;
    loc_ = start_loc;
    return false;
  }
}

Result JSONParser::Expect(const char* s) {
  if (Match(s)) {
    return Result::Ok;
  } else {
    PrintError("expected %s", s);
    return Result::Error;
  }
}

Result JSONParser::ExpectKey(const char* key) {
  size_t keylen = strlen(key);
  size_t quoted_len = keylen + 2 + 1;
  char* quoted = static_cast<char*>(alloca(quoted_len));
  snprintf(quoted, quoted_len, "\"%s\"", key);
  EXPECT(quoted);
  EXPECT(":");
  return Result::Ok;
}

Result JSONParser::ParseUint32(uint32_t* out_int) {
  uint32_t result = 0;
  SkipWhitespace();
  while (1) {
    int c = ReadChar();
    if (c >= '0' && c <= '9') {
      uint32_t last_result = result;
      result = result * 10 + static_cast<uint32_t>(c - '0');
      if (result < last_result) {
        PrintError("uint32 overflow");
        return Result::Error;
      }
    } else {
      PutbackChar();
      break;
    }
  }
  *out_int = result;
  return Result::Ok;
}

Result JSONParser::ParseString(std::string* out_string) {
  out_string->clear();

  SkipWhitespace();
  if (ReadChar() != '"') {
    PrintError("expected string");
    return Result::Error;
  }

  while (1) {
    int c = ReadChar();
    if (c == '"') {
      break;
    } else if (c == '\\') {
      /* The only escape supported is \uxxxx. */
      c = ReadChar();
      if (c != 'u') {
        PrintError("expected escape: \\uxxxx");
        return Result::Error;
      }
      uint16_t code = 0;
      for (int i = 0; i < 4; ++i) {
        c = ReadChar();
        int cval;
        if (c >= '0' && c <= '9') {
          cval = c - '0';
        } else if (c >= 'a' && c <= 'f') {
          cval = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
          cval = c - 'A' + 10;
        } else {
          PrintError("expected hex char");
          return Result::Error;
        }
        code = (code << 4) + cval;
      }

      if (code < 256) {
        *out_string += code;
      } else {
        PrintError("only escape codes < 256 allowed, got %u\n", code);
      }
    } else {
      *out_string += c;
    }
  }
  return Result::Ok;
}

Result JSONParser::ParseKeyStringValue(const char* key,
                                             std::string* out_string) {
  out_string->clear();
  EXPECT_KEY(key);
  return ParseString(out_string);
}

Result JSONParser::ParseOptNameStringValue(std::string* out_string) {
  out_string->clear();
  if (Match("\"name\"")) {
    EXPECT(":");
    CHECK_RESULT(ParseString(out_string));
    EXPECT(",");
  }
  return Result::Ok;
}

Result JSONParser::ParseLine(uint32_t* out_line_number) {
  EXPECT_KEY("line");
  CHECK_RESULT(ParseUint32(out_line_number));
  return Result::Ok;
}

Result JSONParser::ParseTypeObject(Type* out_type) {
  std::string type_str;
  EXPECT("{");
  PARSE_KEY_STRING_VALUE("type", &type_str);
  EXPECT("}");

  if (type_str == "i32") {
    *out_type = Type::I32;
    return Result::Ok;
  } else if (type_str == "f32") {
    *out_type = Type::F32;
    return Result::Ok;
  } else if (type_str == "i64") {
    *out_type = Type::I64;
    return Result::Ok;
  } else if (type_str == "f64") {
    *out_type = Type::F64;
    return Result::Ok;
  } else if (type_str == "v128") {
    *out_type = Type::V128;
    return Result::Ok;
  } else if (type_str == "funcref") {
    *out_type = Type::Funcref;
    return Result::Ok;
  } else if (type_str == "anyref") {
    *out_type = Type::Anyref;
    return Result::Ok;
  } else if (type_str == "nullref") {
    *out_type = Type::Nullref;
    return Result::Ok;
  } else if (type_str == "exnref") {
    *out_type = Type::Exnref;
    return Result::Ok;
  } else {
    PrintError("unknown type: \"%s\"", type_str.c_str());
    return Result::Error;
  }
}

Result JSONParser::ParseTypeVector(TypeVector* out_types) {
  out_types->clear();
  EXPECT("[");
  bool first = true;
  while (!Match("]")) {
    if (!first) {
      EXPECT(",");
    }
    Type type;
    CHECK_RESULT(ParseTypeObject(&type));
    first = false;
    out_types->push_back(type);
  }
  return Result::Ok;
}

Result JSONParser::ParseConst(Value* out_value) {
  std::string type_str;
  std::string value_str;
  EXPECT("{");
  PARSE_KEY_STRING_VALUE("type", &type_str);
  EXPECT(",");
  PARSE_KEY_STRING_VALUE("value", &value_str);
  EXPECT("}");

  return ParseConstValue(out_value, type_str, value_str);
}

Result JSONParser::ParseConstValue(Value* out_value,
                                         string_view type_str,
                                         string_view value_str) {
  const char* value_start = value_str.data();
  const char* value_end = value_str.data() + value_str.size();
  if (type_str == "i32") {
    uint32_t value;
    if (Failed((ParseInt32(value_start, value_end, &value,
                           ParseIntType::UnsignedOnly)))) {
      PrintError("invalid i32 literal");
      return Result::Error;
    }
    out_value->Set(value);
  } else if (type_str == "f32") {
    uint32_t value_bits;
    if (Failed(ParseInt32(value_start, value_end, &value_bits,
                            ParseIntType::UnsignedOnly))) {
      PrintError("invalid f32 literal");
      return Result::Error;
    }
    out_value->Set(Bitcast<f32>(value_bits));
  } else if (type_str == "i64") {
    uint64_t value;
    if (Failed(ParseInt64(value_start, value_end, &value,
                          ParseIntType::UnsignedOnly))) {
      PrintError("invalid i64 literal");
      return Result::Error;
    }
    out_value->Set(value);
  } else if (type_str == "f64") {
    uint64_t value_bits;
    if (Failed((ParseInt64(value_start, value_end, &value_bits,
                           ParseIntType::UnsignedOnly)))) {
      PrintError("invalid f64 literal");
      return Result::Error;
    }
    out_value->Set(Bitcast<f64>(value_bits));
  } else if (type_str == "v128") {
    v128 value_bits;
    if (Failed(ParseUint128(value_start, value_end, &value_bits))) {
      PrintError("invalid v128 literal");
      return Result::Error;
    }
    out_value->Set(value_bits);
  } else if (type_str == "nullref") {
    out_value->Set(Ref::Null);
  } else if (type_str == "hostref") {
    uint32_t value;
    if (Failed(ParseInt32(value_start, value_end, &value,
                          ParseIntType::UnsignedOnly))) {
      PrintError("invalid hostref literal");
      return Result::Error;
    }
    out_value->Set(Ref{value});
  } else if (type_str == "funcref") {
    uint32_t value;
    if (Failed(ParseInt32(value_start, value_end, &value, ParseIntType::UnsignedOnly))) {
      PrintError("invalid funcref literal");
      return Result::Error;
    }
    out_value->Set(Ref{value});
  } else {
    PrintError("unknown concrete type: \"%s\"", type_str.to_string().c_str());
    return Result::Error;
  }

  return Result::Ok;
}

Result JSONParser::ParseExpectedValue(ExpectedValue* out_value) {
  std::string type_str;
  std::string value_str;
  EXPECT("{");
  PARSE_KEY_STRING_VALUE("type", &type_str);
  EXPECT(",");
  PARSE_KEY_STRING_VALUE("value", &value_str);
  EXPECT("}");

  if (type_str == "f32" || type_str == "f64") {
    if (value_str == "nan:canonical") {
      out_value->is_expected_nan = true;
      out_value->expectedNan = ExpectedNan::Canonical;
      return Result::Ok;
    } else if (value_str == "nan:arithmetic") {
      out_value->is_expected_nan = true;
      out_value->expectedNan = ExpectedNan::Arithmetic;
      return Result::Ok;
    }
  }

  out_value->is_expected_nan = false;
  return ParseConstValue(&out_value->value, type_str, value_str);
}

Result JSONParser::ParseExpectedValues(
    std::vector<ExpectedValue>* out_values) {
  out_values->clear();
  EXPECT("[");
  bool first = true;
  while (!Match("]")) {
    if (!first) {
      EXPECT(",");
    }
    ExpectedValue value;
    CHECK_RESULT(ParseExpectedValue(&value));
    out_values->push_back(value);
    first = false;
  }
  return Result::Ok;
}

Result JSONParser::ParseConstVector(Values* out_values) {
  out_values->clear();
  EXPECT("[");
  bool first = true;
  while (!Match("]")) {
    if (!first) {
      EXPECT(",");
    }
    Value value;
    CHECK_RESULT(ParseConst(&value));
    out_values->push_back(value);
    first = false;
  }
  return Result::Ok;
}

Result JSONParser::ParseAction(Action* out_action) {
  EXPECT_KEY("action");
  EXPECT("{");
  EXPECT_KEY("type");
  if (Match("\"invoke\"")) {
    out_action->type = ActionType::Invoke;
  } else {
    EXPECT("\"get\"");
    out_action->type = ActionType::Get;
  }
  EXPECT(",");
  if (Match("\"module\"")) {
    EXPECT(":");
    CHECK_RESULT(ParseString(&out_action->module_name));
    EXPECT(",");
  }
  PARSE_KEY_STRING_VALUE("field", &out_action->field_name);
  if (out_action->type == ActionType::Invoke) {
    EXPECT(",");
    EXPECT_KEY("args");
    CHECK_RESULT(ParseConstVector(&out_action->args));
  }
  EXPECT("}");
  return Result::Ok;
}

Result JSONParser::ParseActionResult() {
  // Not needed for wabt-interp, but useful for other parsers.
  EXPECT_KEY("expected");
  TypeVector expected;
  CHECK_RESULT(ParseTypeVector(&expected));
  return Result::Ok;
}

Result JSONParser::ParseModuleType(ModuleType* out_type) {
  std::string module_type_str;

  PARSE_KEY_STRING_VALUE("module_type", &module_type_str);
  if (module_type_str == "text") {
    *out_type = ModuleType::Text;
    return Result::Ok;
  } else if (module_type_str == "binary") {
    *out_type = ModuleType::Binary;
    return Result::Ok;
  } else {
    PrintError("unknown module type: \"%s\"", module_type_str.c_str());
    return Result::Error;
  }
}

static string_view GetDirname(string_view path) {
  // Strip everything after and including the last slash (or backslash), e.g.:
  //
  // s = "foo/bar/baz", => "foo/bar"
  // s = "/usr/local/include/stdio.h", => "/usr/local/include"
  // s = "foo.bar", => ""
  // s = "some\windows\directory", => "some\windows"
  size_t last_slash = path.find_last_of('/');
  size_t last_backslash = path.find_last_of('\\');
  if (last_slash == string_view::npos) {
    last_slash = 0;
  }
  if (last_backslash == string_view::npos) {
    last_backslash = 0;
  }

  return path.substr(0, std::max(last_slash, last_backslash));
}

std::string JSONParser::CreateModulePath(string_view filename) {
  string_view spec_json_filename = loc_.filename;
  string_view dirname = GetDirname(spec_json_filename);
  std::string path;

  if (dirname.size() == 0) {
    path = filename.to_string();
  } else {
    path = dirname.to_string();
    path += '/';
    path += filename.to_string();
  }

  ConvertBackslashToSlash(&path);
  return path;
}

Result JSONParser::ParseFilename(std::string* out_filename) {
  PARSE_KEY_STRING_VALUE("filename", out_filename);
  *out_filename = CreateModulePath(*out_filename);
  return Result::Ok;
}

Result JSONParser::ParseCommand(CommandPtr* out_command) {
  EXPECT("{");
  EXPECT_KEY("type");
  if (Match("\"module\"")) {
    auto command = MakeUnique<ModuleCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseOptNameStringValue(&command->name));
    CHECK_RESULT(ParseFilename(&command->filename));
    *out_command = std::move(command);
  } else if (Match("\"action\"")) {
    auto command = MakeUnique<ActionCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseAction(&command->action));
    EXPECT(",");
    CHECK_RESULT(ParseActionResult());
    *out_command = std::move(command);
  } else if (Match("\"register\"")) {
    auto command = MakeUnique<RegisterCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseOptNameStringValue(&command->name));
    PARSE_KEY_STRING_VALUE("as", &command->as);
    *out_command = std::move(command);
  } else if (Match("\"assert_malformed\"")) {
    auto command = MakeUnique<AssertMalformedCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseFilename(&command->filename));
    EXPECT(",");
    PARSE_KEY_STRING_VALUE("text", &command->text);
    EXPECT(",");
    CHECK_RESULT(ParseModuleType(&command->type));
    *out_command = std::move(command);
  } else if (Match("\"assert_invalid\"")) {
    auto command = MakeUnique<AssertInvalidCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseFilename(&command->filename));
    EXPECT(",");
    PARSE_KEY_STRING_VALUE("text", &command->text);
    EXPECT(",");
    CHECK_RESULT(ParseModuleType(&command->type));
    *out_command = std::move(command);
  } else if (Match("\"assert_unlinkable\"")) {
    auto command = MakeUnique<AssertUnlinkableCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseFilename(&command->filename));
    EXPECT(",");
    PARSE_KEY_STRING_VALUE("text", &command->text);
    EXPECT(",");
    CHECK_RESULT(ParseModuleType(&command->type));
    *out_command = std::move(command);
  } else if (Match("\"assert_uninstantiable\"")) {
    auto command = MakeUnique<AssertUninstantiableCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseFilename(&command->filename));
    EXPECT(",");
    PARSE_KEY_STRING_VALUE("text", &command->text);
    EXPECT(",");
    CHECK_RESULT(ParseModuleType(&command->type));
    *out_command = std::move(command);
  } else if (Match("\"assert_return\"")) {
    auto command = MakeUnique<AssertReturnCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseAction(&command->action));
    EXPECT(",");
    EXPECT_KEY("expected");
    CHECK_RESULT(ParseExpectedValues(&command->expected));
    *out_command = std::move(command);
  } else if (Match("\"assert_trap\"")) {
    auto command = MakeUnique<AssertTrapCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseAction(&command->action));
    EXPECT(",");
    PARSE_KEY_STRING_VALUE("text", &command->text);
    EXPECT(",");
    CHECK_RESULT(ParseActionResult());
    *out_command = std::move(command);
  } else if (Match("\"assert_exhaustion\"")) {
    auto command = MakeUnique<AssertExhaustionCommand>();
    EXPECT(",");
    CHECK_RESULT(ParseLine(&command->line));
    EXPECT(",");
    CHECK_RESULT(ParseAction(&command->action));
    EXPECT(",");
    PARSE_KEY_STRING_VALUE("text", &command->text);
    EXPECT(",");
    CHECK_RESULT(ParseActionResult());
    *out_command = std::move(command);
  } else {
    PrintError("unknown command type");
    return Result::Error;
  }
  EXPECT("}");
  return Result::Ok;
}

Result JSONParser::ParseScript(Script* out_script) {
  EXPECT("{");
  PARSE_KEY_STRING_VALUE("source_filename", &out_script->filename);
  EXPECT(",");
  EXPECT_KEY("commands");
  EXPECT("[");
  bool first = true;
  while (!Match("]")) {
    CommandPtr command;
    if (!first) {
      EXPECT(",");
    }
    CHECK_RESULT(ParseCommand(&command));
    out_script->commands.push_back(std::move(command));
    first = false;
  }
  EXPECT("}");
  return Result::Ok;
}

struct ActionResult {
  ValueTypes types;
  Values values;
  Trap::Ptr trap;
};

class CommandRunner {
 public:
  CommandRunner();
  Result Run(const Script& script);

  int passed() const { return passed_; }
  int total() const { return total_; }

 private:
  using ExternMap = std::map<std::string, Extern::Ptr>;
  using Registry = std::map<std::string, ExternMap>;
  using InstanceMap = std::map<std::string, Instance::Ptr>;

  void WABT_PRINTF_FORMAT(3, 4)
      PrintError(uint32_t line_number, const char* format, ...);
  ActionResult RunAction(int line_number,
                         const Action* action,
                         RunVerbosity verbose);

  interp2::Module::Ptr ReadModule(string_view module_filename, Errors* errors);
  Extern::Ptr GetExtern(const std::string&, const std::string&);
  void PopulateImports(const interp2::Module::Ptr&, RefVec*);
  void PopulateExports(const Instance::Ptr&, ExternMap*);

  Result OnModuleCommand(const ModuleCommand*);
  Result OnActionCommand(const ActionCommand*);
  Result OnRegisterCommand(const RegisterCommand*);
  Result OnAssertMalformedCommand(const AssertMalformedCommand*);
  Result OnAssertUnlinkableCommand(const AssertUnlinkableCommand*);
  Result OnAssertInvalidCommand(const AssertInvalidCommand*);
  Result OnAssertUninstantiableCommand(
      const AssertUninstantiableCommand*);
  Result OnAssertReturnCommand(const AssertReturnCommand*);
  Result OnAssertTrapCommand(const AssertTrapCommand*);
  Result OnAssertExhaustionCommand(const AssertExhaustionCommand*);

  void TallyCommand(Result);

  Result ReadInvalidTextModule(string_view module_filename,
                                     const std::string& header);
  Result ReadInvalidModule(int line_number,
                           string_view module_filename,
                           ModuleType module_type,
                           const char* desc);
  Result ReadUnlinkableModule(int line_number,
                              string_view module_filename,
                              ModuleType module_type,
                              const char* desc);

  Store store_;
  Registry registry_;
  InstanceMap instances_;
  ExternMap last_exports_;
  int passed_ = 0;
  int total_ = 0;

  std::string source_filename_;
};

CommandRunner::CommandRunner() {
  auto&& spectest = registry_["spectest"];

  // Initialize print functions for the spec test.
  struct {
    const char* name;
    interp2::FuncType type;
  } const print_funcs[] = {
      {"print", interp2::FuncType{{}, {}}},
      {"print_i32", interp2::FuncType{{ValueType::I32}, {}}},
      {"print_f32", interp2::FuncType{{ValueType::F32}, {}}},
      {"print_f64", interp2::FuncType{{ValueType::F64}, {}}},
      {"print_i32_f32", interp2::FuncType{{ValueType::I32, ValueType::F32}, {}}},
      {"print_f64_f64", interp2::FuncType{{ValueType::F64, ValueType::F64}, {}}},
  };

  for (auto&& print : print_funcs) {
    auto import_name = StringPrintf("spectest.%s", print.name);
    spectest[print.name] = HostFunc::New(
        store_, print.type,
        [=](const Values& params, Values& results, Trap::Ptr* trap) -> Result {
          printf("called host ");
          WriteCall(s_stdout_stream.get(), import_name, print.type, params,
                    results, *trap);
          return Result::Ok;
        });
  }

  spectest["table"] = interp2::Table::New(
      store_, TableType{ValueType::Funcref, Limits{10, 20}});

  spectest["memory"] =
      interp2::Memory::New(store_, MemoryType{Limits{1, 2}});

  spectest["global_i32"] = interp2::Global::New(
      store_, GlobalType{ValueType::I32, Mutability::Const}, Value(u32{666}));
  spectest["global_i64"] = interp2::Global::New(
      store_, GlobalType{ValueType::I64, Mutability::Const}, Value(u64{666}));
  spectest["global_f32"] = interp2::Global::New(
      store_, GlobalType{ValueType::F32, Mutability::Const}, Value(f32{666}));
  spectest["global_f64"] = interp2::Global::New(
      store_, GlobalType{ValueType::F64, Mutability::Const}, Value(f64{666}));
}

Result CommandRunner::Run(const Script& script) {
  source_filename_ = script.filename;

  for (const CommandPtr& command : script.commands) {
    switch (command->type) {
      case CommandType::Module:
        OnModuleCommand(cast<ModuleCommand>(command.get()));
        break;

      case CommandType::Action:
        TallyCommand(OnActionCommand(cast<ActionCommand>(command.get())));
        break;

      case CommandType::Register:
        OnRegisterCommand(cast<RegisterCommand>(command.get()));
        break;

      case CommandType::AssertMalformed:
        TallyCommand(OnAssertMalformedCommand(
            cast<AssertMalformedCommand>(command.get())));
        break;

      case CommandType::AssertInvalid:
        TallyCommand(
            OnAssertInvalidCommand(cast<AssertInvalidCommand>(command.get())));
        break;

      case CommandType::AssertUnlinkable:
        TallyCommand(OnAssertUnlinkableCommand(
            cast<AssertUnlinkableCommand>(command.get())));
        break;

      case CommandType::AssertUninstantiable:
        TallyCommand(OnAssertUninstantiableCommand(
            cast<AssertUninstantiableCommand>(command.get())));
        break;

      case CommandType::AssertReturn:
        TallyCommand(
            OnAssertReturnCommand(cast<AssertReturnCommand>(command.get())));
        break;

      case CommandType::AssertTrap:
        TallyCommand(
            OnAssertTrapCommand(cast<AssertTrapCommand>(command.get())));
        break;

      case CommandType::AssertExhaustion:
        TallyCommand(OnAssertExhaustionCommand(
            cast<AssertExhaustionCommand>(command.get())));
        break;
    }
  }

  return Result::Ok;
}

void CommandRunner::PrintError(uint32_t line_number, const char* format, ...) {
  WABT_SNPRINTF_ALLOCA(buffer, length, format);
  printf("%s:%u: %s\n", source_filename_.c_str(), line_number, buffer);
}

ActionResult CommandRunner::RunAction(int line_number,
                                      const Action* action,
                                      RunVerbosity verbose) {
  ExternMap& module = !action->module_name.empty()
                          ? registry_[action->module_name]
                          : last_exports_;
  Extern::Ptr extern_ = module[action->field_name];

  ActionResult result;

  switch (action->type) {
    case ActionType::Invoke: {
      auto* func = cast<interp2::Func>(extern_.get());
      func->Call(store_, action->args, result.values, &result.trap,
                 s_trace_stream);
      result.types = func->func_type().results;
      if (verbose == RunVerbosity::Verbose) {
        WriteCall(s_stdout_stream.get(), action->field_name, func->func_type(),
                  action->args, result.values, result.trap);
      }
      break;
    }

    case ActionType::Get: {
      auto* global = cast<interp2::Global>(extern_.get());
      result.values.push_back(global->Get());
      result.types.push_back(global->type().type);
      break;
    }

    default:
      WABT_UNREACHABLE;
  }

  return result;
}

Result CommandRunner::ReadInvalidTextModule(string_view module_filename,
                                            const std::string& header) {
  std::vector<uint8_t> file_data;
  Result result = ReadFile(module_filename, &file_data);
  std::unique_ptr<WastLexer> lexer = WastLexer::CreateBufferLexer(
      module_filename, file_data.data(), file_data.size());
  Errors errors;
  if (Succeeded(result)) {
    std::unique_ptr<::Script> script;
    WastParseOptions options(s_features);
    result = ParseWastScript(lexer.get(), &script, &errors, &options);
    if (Succeeded(result)) {
      wabt::Module* module = script->GetFirstModule();
      result = ResolveNamesModule(module, &errors);
      if (Succeeded(result)) {
        ValidateOptions options(s_features);
        // Don't do a full validation, just validate the function signatures.
        result = ValidateFuncSignatures(module, &errors, options);
      }
    }
  }

  auto line_finder = lexer->MakeLineFinder();
  FormatErrorsToFile(errors, Location::Type::Text, line_finder.get(), stdout,
                     header, PrintHeader::Once);
  return result;
}

interp2::Module::Ptr CommandRunner::ReadModule(string_view module_filename,
                                               Errors* errors) {
  std::vector<uint8_t> file_data;

  if (Failed(ReadFile(module_filename, &file_data))) {
    return {};
  }

  const bool kReadDebugNames = true;
  const bool kStopOnFirstError = true;
  const bool kFailOnCustomSectionError = true;
  ReadBinaryOptions options(s_features, s_log_stream.get(), kReadDebugNames,
                            kStopOnFirstError, kFailOnCustomSectionError);
  ModuleDesc module_desc;
  if (Failed(interp2::ReadModule(file_data.data(), file_data.size(), options,
                                 errors, &module_desc))) {
    return {};
  }

  if (s_verbose) {
    module_desc.istream.Disassemble(s_stdout_stream.get());
  }

  return interp2::Module::New(store_, module_desc);
}

Result CommandRunner::ReadInvalidModule(int line_number,
                                        string_view module_filename,
                                        ModuleType module_type,
                                        const char* desc) {
  std::string header = StringPrintf(
      "%s:%d: %s passed", source_filename_.c_str(), line_number, desc);

  switch (module_type) {
    case ModuleType::Text: {
      return ReadInvalidTextModule(module_filename, header);
    }

    case ModuleType::Binary: {
      Errors errors;
      auto module = ReadModule(module_filename, &errors);
      if (!module) {
        FormatErrorsToFile(errors, Location::Type::Binary, {}, stdout, header,
                           PrintHeader::Once);
        return Result::Error;
      } else {
        return Result::Ok;
      }
    }
  }

  WABT_UNREACHABLE;
}

Extern::Ptr CommandRunner::GetExtern(const std::string& module,
                                     const std::string& name) {
  auto mod_iter = registry_.find(module);
  if (mod_iter != registry_.end()) {
    auto extern_iter = mod_iter->second.find(name);
    if (extern_iter != mod_iter->second.end()) {
      return extern_iter->second;
    }
  }
  return {};
}

void CommandRunner::PopulateImports(const interp2::Module::Ptr& module,
                                    RefVec* imports) {
  for (auto&& import : module->desc().imports) {
    auto extern_ = GetExtern(import.type.module, import.type.name);
    imports->push_back(extern_ ? extern_.ref() : Ref::Null);
  }
}

void CommandRunner::PopulateExports(const Instance::Ptr& instance,
                                    ExternMap* map) {
  interp2::Module::Ptr module{store_, instance->module()};
  for (size_t i = 0; i < module->export_types().size(); ++i) {
    const ExportType& export_type = module->export_types()[i];
    (*map)[export_type.name] = store_.UnsafeGet<Extern>(instance->exports()[i]);
  }
}

Result CommandRunner::OnModuleCommand(const ModuleCommand* command) {
  Errors errors;
  auto module = ReadModule(command->filename, &errors);
  FormatErrorsToFile(errors, Location::Type::Binary);

  if (!module) {
    PrintError(command->line, "error reading module: \"%s\"",
               command->filename.c_str());
    return Result::Error;
  }

  RefVec imports;
  PopulateImports(module, &imports);

  Trap::Ptr trap;
  auto instance = Instance::Instantiate(store_, module.ref(), imports, &trap);
  if (trap) {
    assert(!instance);
    PrintError(command->line, "error instantiating module: \"%s\"",
               trap->message().c_str());
    return Result::Error;
  }

  PopulateExports(instance, &last_exports_);
  if (!command->name.empty()) {
    instances_[command->name] = instance;
  }

  return Result::Ok;
}

Result CommandRunner::OnActionCommand(const ActionCommand* command) {
  ActionResult result =
      RunAction(command->line, &command->action, RunVerbosity::Verbose);

  if (result.trap) {
    PrintError(command->line, "unexpected trap: %s",
               result.trap->message().c_str());
    return Result::Error;
  }

  return Result::Ok;
}

Result CommandRunner::OnAssertMalformedCommand(
    const AssertMalformedCommand* command) {
  Result result = ReadInvalidModule(command->line, command->filename,
                                    command->type, "assert_malformed");
  if (Succeeded(result)) {
    PrintError(command->line, "expected module to be malformed: \"%s\"",
               command->filename.c_str());
    return Result::Error;
  }

  return Result::Ok;
}

Result CommandRunner::OnRegisterCommand(const RegisterCommand* command) {
  if (!command->name.empty()) {
    auto instance_iter = instances_.find(command->name);
    if (instance_iter == instances_.end()) {
      PrintError(command->line, "unknown module in register");
      return Result::Error;
    }
    auto& extern_map = registry_[command->as];
    PopulateExports(instance_iter->second, &extern_map);
  } else {
    registry_[command->as] = last_exports_;
  }

  return Result::Ok;
}

Result CommandRunner::OnAssertUnlinkableCommand(
    const AssertUnlinkableCommand* command) {
  Errors errors;
  auto module = ReadModule(command->filename, &errors);

  if (!module) {
    PrintError(command->line, "unable to compile unlinkable module: \"%s\"",
               command->filename.c_str());
    return Result::Error;
  }

  RefVec imports;
  PopulateImports(module, &imports);

  Trap::Ptr trap;
  auto instance = Instance::Instantiate(store_, module.ref(), imports, &trap);
  if (!trap) {
    PrintError(command->line, "expected module to be unlinkable: \"%s\"",
               command->filename.c_str());
    return Result::Error;
  }

  s_stdout_stream->Writef("assert_unlinkable passed: %s",
                          trap->message().c_str());
  return Result::Ok;
}

Result CommandRunner::OnAssertInvalidCommand(
    const AssertInvalidCommand* command) {
  Result result = ReadInvalidModule(command->line, command->filename,
                                    command->type, "assert_invalid");
  if (Succeeded(result)) {
    PrintError(command->line, "expected module to be invalid: \"%s\"",
               command->filename.c_str());
    return Result::Error;
  }

  return Result::Ok;
}

Result CommandRunner::OnAssertUninstantiableCommand(
    const AssertUninstantiableCommand* command) {
  Errors errors;
  auto module = ReadModule(command->filename, &errors);

  if (!module) {
    PrintError(command->line, "unable to compile uninstantiable module: \"%s\"",
               command->filename.c_str());
    return Result::Error;
  }

  RefVec imports;
  PopulateImports(module, &imports);

  Trap::Ptr trap;
  auto instance = Instance::Instantiate(store_, module.ref(), imports, &trap);
  if (!trap) {
    PrintError(command->line, "expected module to be uninstantiable: \"%s\"",
               command->filename.c_str());
    return Result::Error;
  }

  s_stdout_stream->Writef("assert_uninstantiable passed: %s",
                          trap->message().c_str());
  return Result::Ok;
}

static bool ValuesAreEqual(ValueType type, Value v1, Value v2) {
  switch (type) {
    case Type::I32: return v1.Get<u32>() == v2.Get<u32>();
    case Type::F32: return Bitcast<u32>(v1.Get<f32>()) == Bitcast<u32>(v2.Get<f32>());
    case Type::I64: return v1.Get<u64>() == v2.Get<u64>();
    case Type::F64: return Bitcast<u64>(v1.Get<f64>()) == Bitcast<u64>(v2.Get<f64>());
    case Type::V128: return v1.Get<v128>() == v2.Get<v128>();
    case Type::Nullref: return true;

    case Type::Funcref:
    case Type::Hostref:
    case Type::Exnref:
    case Type::Anyref:
      return v1.Get<Ref>() == v2.Get<Ref>();
    default:
      WABT_UNREACHABLE;
  }
}

static bool IsCanonicalNan(f32 val) {
  const u32 kQuietNan = 0x7fc00000U;
  const u32 kQuietNegNan = 0xffc00000U;
  u32 bits = Bitcast<u32>(val);
  return bits == kQuietNan || bits == kQuietNegNan;
}

static bool IsCanonicalNan(f64 val) {
  const u64 kQuietNan = 0x7ff8000000000000ULL;
  const u64 kQuietNegNan = 0xfff8000000000000ULL;
  u64 bits = Bitcast<u64>(val);
  return bits == kQuietNan || bits == kQuietNegNan;
}

static bool IsArithmeticNan(f32 val) {
  const u32 kQuietNan = 0x7fc00000U;
  return (Bitcast<u32>(val) & kQuietNan) == kQuietNan;
}

static bool IsArithmeticNan(f64 val) {
  const u64 kQuietNan = 0x7ff8000000000000ULL;
  return (Bitcast<u64>(val) & kQuietNan) == kQuietNan;
}

Result CommandRunner::OnAssertReturnCommand(
    const AssertReturnCommand* command) {
  ActionResult action_result =
      RunAction(command->line, &command->action, RunVerbosity::Quiet);

  if (action_result.trap) {
    PrintError(command->line, "unexpected trap: %s",
               action_result.trap->message().c_str());
    return Result::Error;
  }

  if (action_result.values.size() != command->expected.size()) {
    PrintError(command->line,
               "result length mismatch in assert_return: expected %" PRIzd
               ", got %" PRIzd,
               command->expected.size(), action_result.values.size());
    return Result::Error;
  }

  Result result = Result::Ok;
  for (size_t i = 0; i < action_result.values.size(); ++i) {
    const ExpectedValue& expected = command->expected[i];
    const Value& actual = action_result.values[i];
    ValueType type = action_result.types[i];

    if (expected.is_expected_nan) {
      bool is_nan;
      if (expected.expectedNan == ExpectedNan::Arithmetic) {
        if (type == Type::F64) {
          is_nan = IsArithmeticNan(actual.Get<f64>());
        } else {
          is_nan = IsArithmeticNan(actual.Get<f32>());
        }
      } else if (expected.expectedNan == ExpectedNan::Canonical) {
        if (type == Type::F64) {
          is_nan = IsCanonicalNan(actual.Get<f64>());
        } else {
          is_nan = IsCanonicalNan(actual.Get<f32>());
        }
      } else {
        WABT_UNREACHABLE;
      }
      if (!is_nan) {
        PrintError(command->line, "expected result to be nan, got %s",
                   TypedValueToString(type, actual).c_str());
        result = Result::Error;
      }
    } else if (type == Type::Funcref) {
      if (type != Type::Funcref) {
        PrintError(command->line,
                   "mismatch in result %" PRIzd
                   " of assert_return: expected funcref, got %s",
                   i, TypedValueToString(type, actual).c_str());
      }
    } else {
      if (!ValuesAreEqual(type, expected.value, actual)) {
        PrintError(command->line,
                   "mismatch in result %" PRIzd
                   " of assert_return: expected %s, got %s",
                   i, TypedValueToString(type, expected.value).c_str(),
                   TypedValueToString(type, actual).c_str());
        result = Result::Error;
      }
    }
  }

  return result;
}

Result CommandRunner::OnAssertTrapCommand(
    const AssertTrapCommand* command) {
  ActionResult result =
      RunAction(command->line, &command->action, RunVerbosity::Quiet);
  if (!result.trap) {
    PrintError(command->line, "expected trap: \"%s\"", command->text.c_str());
    return Result::Error;
  }

  PrintError(command->line, "assert_trap passed: %s",
             result.trap->message().c_str());
  return Result::Ok;
}

Result CommandRunner::OnAssertExhaustionCommand(
    const AssertExhaustionCommand* command) {
  ActionResult result =
      RunAction(command->line, &command->action, RunVerbosity::Quiet);
  if (!result.trap) {
    PrintError(command->line, "expected trap: \"%s\"", command->text.c_str());
    return Result::Error;
  }

  PrintError(command->line, "assert_trap passed: %s",
             result.trap->message().c_str());
  return Result::Ok;
}

void CommandRunner::TallyCommand(Result result) {
  if (Succeeded(result)) {
    passed_++;
  }
  total_++;
}

static int ReadAndRunSpecJSON(string_view spec_json_filename) {
  JSONParser parser;
  if (parser.ReadFile(spec_json_filename) == Result::Error) {
    return 1;
  }

  Script script;
  if (parser.ParseScript(&script) == Result::Error) {
    return 1;
  }

  CommandRunner runner;
  if (runner.Run(script) == Result::Error) {
    return 1;
  }

  printf("%d/%d tests passed.\n", runner.passed(), runner.total());
  const int failed = runner.total() - runner.passed();
  return failed;
}

}  // namespace spectest

int ProgramMain(int argc, char** argv) {
  InitStdio();
  s_stdout_stream = FileStream::CreateStdout();

  ParseOptions(argc, argv);
  return spectest::ReadAndRunSpecJSON(s_infile);
}

int main(int argc, char** argv) {
  WABT_TRY
  return ProgramMain(argc, argv);
  WABT_CATCH_BAD_ALLOC_AND_EXIT
}
