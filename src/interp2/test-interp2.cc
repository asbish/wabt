/*
 * Copyright 2020 WebAssembly Community Group participants
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

#include "gtest/gtest.h"

#include "src/binary-reader.h"
#include "src/error-formatter.h"

#include "src/interp2/interp2-math.h"
#include "src/interp2/interp2.h"
#include "src/interp2/istream.h"
#include "src/interp2/read-module.h"

using namespace wabt;
using namespace wabt::interp2;

class Interp2Test : public ::testing::Test {
 public:
  virtual void SetUp() {}
  virtual void TearDown() {}

  void ReadModule(const std::vector<u8>& data) {
    Errors errors;
    ReadBinaryOptions options;
    Result result =
        ::ReadModule(data.data(), data.size(), options, &errors, &module_desc_);
    ASSERT_EQ(Result::Ok, result)
        << FormatErrorsToString(errors, Location::Type::Binary);
  }

  void Instantiate(const RefVec& imports = RefVec{}) {
    mod_ = Module::New(store_, module_desc_);
    RefPtr<Trap> trap;
    inst_ = Instance::Instantiate(store_, mod_.ref(), imports, &trap);
    ASSERT_TRUE(inst_) << trap->message();
  }

  DefinedFunc::Ptr GetFuncExport(Index index) {
    EXPECT_LT(index, inst_->exports().size());
    return store_.UnsafeGet<DefinedFunc>(inst_->exports()[index]);
  }

  void ExpectBufferStrEq(OutputBuffer& buf, const char* str) {
    char buf_str[buf.size() + 1];
    memcpy(buf_str, buf.data.data(), sizeof(buf_str));
    buf_str[buf.size()] = 0;
    EXPECT_STREQ(buf_str, str);
  }

  Store store_;
  ModuleDesc module_desc_;
  Module::Ptr mod_;
  Instance::Ptr inst_;
};


TEST_F(Interp2Test, Empty) {
  ReadModule({0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00});
}

TEST_F(Interp2Test, MVP) {
  // (module
  //   (type (;0;) (func (param i32) (result i32)))
  //   (type (;1;) (func (param f32) (result f32)))
  //   (type (;2;) (func))
  //   (import "foo" "bar" (func (;0;) (type 0)))
  //   (func (;1;) (type 1) (param f32) (result f32)
  //     (f32.const 0x1.5p+5 (;=42;)))
  //   (func (;2;) (type 2))
  //   (table (;0;) 1 2 funcref)
  //   (memory (;0;) 1)
  //   (global (;0;) i32 (i32.const 1))
  //   (export "quux" (func 1))
  //   (start 2)
  //   (elem (;0;) (i32.const 0) 0 1)
  //   (data (;0;) (i32.const 2) "hello"))
  ReadModule({
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x03, 0x60,
      0x01, 0x7f, 0x01, 0x7f, 0x60, 0x01, 0x7d, 0x01, 0x7d, 0x60, 0x00, 0x00,
      0x02, 0x0b, 0x01, 0x03, 0x66, 0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72, 0x00,
      0x00, 0x03, 0x03, 0x02, 0x01, 0x02, 0x04, 0x05, 0x01, 0x70, 0x01, 0x01,
      0x02, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x00, 0x41,
      0x01, 0x0b, 0x07, 0x08, 0x01, 0x04, 0x71, 0x75, 0x75, 0x78, 0x00, 0x01,
      0x08, 0x01, 0x02, 0x09, 0x08, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x02, 0x00,
      0x01, 0x0a, 0x0c, 0x02, 0x07, 0x00, 0x43, 0x00, 0x00, 0x28, 0x42, 0x0b,
      0x02, 0x00, 0x0b, 0x0b, 0x0b, 0x01, 0x00, 0x41, 0x02, 0x0b, 0x05, 0x68,
      0x65, 0x6c, 0x6c, 0x6f,
  });

  EXPECT_EQ(3u, module_desc_.func_types.size());
  EXPECT_EQ(1u, module_desc_.imports.size());
  EXPECT_EQ(2u, module_desc_.funcs.size());
  EXPECT_EQ(1u, module_desc_.tables.size());
  EXPECT_EQ(1u, module_desc_.memories.size());
  EXPECT_EQ(1u, module_desc_.globals.size());
  EXPECT_EQ(0u, module_desc_.events.size());
  EXPECT_EQ(1u, module_desc_.exports.size());
  EXPECT_EQ(1u, module_desc_.starts.size());
  EXPECT_EQ(1u, module_desc_.elems.size());
  EXPECT_EQ(1u, module_desc_.datas.size());
}

namespace {

// (func (export "fac") (param $n i32) (result i32)
//   (local $result i32)
//   (local.set $result (i32.const 1))
//   (loop (result i32)
//     (local.set $result
//       (i32.mul
//         (br_if 1 (local.get $result) (i32.eqz (local.get $n)))
//         (local.get $n)))
//     (local.set $n (i32.sub (local.get $n) (i32.const 1)))
//     (br 0)))
const std::vector<u8> s_fac_module = {
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01,
    0x60, 0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07,
    0x01, 0x03, 0x66, 0x61, 0x63, 0x00, 0x00, 0x0a, 0x22, 0x01, 0x20,
    0x01, 0x01, 0x7f, 0x41, 0x01, 0x21, 0x01, 0x03, 0x7f, 0x20, 0x01,
    0x20, 0x00, 0x45, 0x0d, 0x01, 0x20, 0x00, 0x6c, 0x21, 0x01, 0x20,
    0x00, 0x41, 0x01, 0x6b, 0x21, 0x00, 0x0c, 0x00, 0x0b, 0x0b,
};

}  // namespace

TEST_F(Interp2Test, Disassemble) {
  ReadModule(s_fac_module);

  MemoryStream stream;
  module_desc_.istream.Disassemble(&stream);
  auto buf = stream.ReleaseOutputBuffer();

  ExpectBufferStrEq(*buf,
R"(   0| alloca 1
   6| i32.const 1
  12| local.set $1, %[-1]
  18| local.get $1
  24| local.get $3
  30| i32.eqz %[-1]
  32| br_unless @44, %[-1]
  38| br @84
  44| local.get $3
  50| i32.mul %[-2], %[-1]
  52| local.set $1, %[-1]
  58| local.get $2
  64| i32.const 1
  70| i32.sub %[-2], %[-1]
  72| local.set $2, %[-1]
  78| br @18
  84| drop_keep $2 $1
  94| return
)");
}

TEST_F(Interp2Test, Fac) {
  ReadModule(s_fac_module);
  Instantiate();
  auto func = GetFuncExport(0);

  Values results;
  Trap::Ptr trap;
  Result result = func->Call(store_, {Value(5)}, results, &trap);

  ASSERT_EQ(Result::Ok, result);
  EXPECT_EQ(1u, results.size());
  EXPECT_EQ(120u, results[0].Get<u32>());
}

TEST_F(Interp2Test, Fac_Trace) {
  ReadModule(s_fac_module);
  Instantiate();
  auto func = GetFuncExport(0);

  Values results;
  Trap::Ptr trap;
  MemoryStream stream;
  Result result = func->Call(store_, {Value(2)}, results, &trap, &stream);
  ASSERT_EQ(Result::Ok, result);

  auto buf = stream.ReleaseOutputBuffer();
  ExpectBufferStrEq(*buf,
R"(   0| alloca 1
   6| i32.const 1
  12| local.set $1, 1
  18| local.get $1
  24| local.get $3
  30| i32.eqz 2
  32| br_unless @44, 0
  44| local.get $3
  50| i32.mul 1, 2
  52| local.set $1, 2
  58| local.get $2
  64| i32.const 1
  70| i32.sub 2, 1
  72| local.set $2, 1
  78| br @18
  18| local.get $1
  24| local.get $3
  30| i32.eqz 1
  32| br_unless @44, 0
  44| local.get $3
  50| i32.mul 2, 1
  52| local.set $1, 2
  58| local.get $2
  64| i32.const 1
  70| i32.sub 1, 1
  72| local.set $2, 0
  78| br @18
  18| local.get $1
  24| local.get $3
  30| i32.eqz 0
  32| br_unless @44, 1
  38| br @84
  84| drop_keep $2 $1
  94| return
)");
}

TEST_F(Interp2Test, Local_Trace) {
  // (func (export "a")
  //   (local i32 i64 f32 f64)
  //   (local.set 0 (i32.const 0))
  //   (local.set 1 (i64.const 1))
  //   (local.set 2 (f32.const 2))
  //   (local.set 3 (f64.const 3)))
  ReadModule({
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01,
      0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x07, 0x05, 0x01, 0x01,
      0x61, 0x00, 0x00, 0x0a, 0x26, 0x01, 0x24, 0x04, 0x01, 0x7f, 0x01,
      0x7e, 0x01, 0x7d, 0x01, 0x7c, 0x41, 0x00, 0x21, 0x00, 0x42, 0x01,
      0x21, 0x01, 0x43, 0x00, 0x00, 0x00, 0x40, 0x21, 0x02, 0x44, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x21, 0x03, 0x0b,
  });

  Instantiate();
  auto func = GetFuncExport(0);

  Values results;
  Trap::Ptr trap;
  MemoryStream stream;
  Result result = func->Call(store_, {}, results, &trap, &stream);
  ASSERT_EQ(Result::Ok, result);

  auto buf = stream.ReleaseOutputBuffer();
  ExpectBufferStrEq(*buf,
R"(   0| alloca 4
   6| i32.const 0
  12| local.set $4, 0
  18| i64.const 1
  28| local.set $3, 1
  34| f32.const 2
  40| local.set $2, 2
  46| f64.const 3
  56| local.set $1, 3
  62| drop_keep $4 $0
  72| return
)");
}

TEST_F(Interp2Test, HostFunc) {
  // (import "" "f" (func $f (param i32) (result i32)))
  // (func (export "g") (result i32)
  //   (call $f (i32.const 1)))
  ReadModule({
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a,
      0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f,
      0x02, 0x06, 0x01, 0x00, 0x01, 0x66, 0x00, 0x00, 0x03, 0x02,
      0x01, 0x01, 0x07, 0x05, 0x01, 0x01, 0x67, 0x00, 0x01, 0x0a,
      0x08, 0x01, 0x06, 0x00, 0x41, 0x01, 0x10, 0x00, 0x0b,
  });

  auto host_func = HostFunc::New(
      store_, FuncType{{ValueType::I32}, {ValueType::I32}},
      [](const Values& params, Values& results, Trap::Ptr* out_trap) -> Result {
        results[0] = Value(params[0].Get<u32>() + 1);
        return Result::Ok;
      });

  Instantiate({host_func->self()});

  Values results;
  Trap::Ptr trap;
  Result result = GetFuncExport(0)->Call(store_, {}, results, &trap);

  ASSERT_EQ(Result::Ok, result);
  EXPECT_EQ(1u, results.size());
  EXPECT_EQ(2u, results[0].Get<u32>());
}

TEST_F(Interp2Test, HostFunc_PingPong) {
  // (import "" "f" (func $f (param i32) (result i32)))
  // (func (export "g") (param i32) (result i32)
  //   (call $f (i32.add (local.get 0) (i32.const 1))))
  ReadModule({
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60,
      0x01, 0x7f, 0x01, 0x7f, 0x02, 0x06, 0x01, 0x00, 0x01, 0x66, 0x00, 0x00,
      0x03, 0x02, 0x01, 0x00, 0x07, 0x05, 0x01, 0x01, 0x67, 0x00, 0x01, 0x0a,
      0x0b, 0x01, 0x09, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x10, 0x00, 0x0b,
  });

  auto host_func = HostFunc::New(
      store_, FuncType{{ValueType::I32}, {ValueType::I32}},
      [&](const Values& params, Values& results,
          Trap::Ptr* out_trap) -> Result {
        auto val = params[0].Get<u32>();
        if (val < 10) {
          return GetFuncExport(0)->Call(store_, {Value(val * 2)}, results,
                                        out_trap);
        }
        results[0] = Value(val);
        return Result::Ok;
      });

  Instantiate({host_func->self()});

  // Should produce the following calls:
  //  g(1) -> f(2) -> g(4) -> f(5) -> g(10) -> f(11) -> return 11

  Values results;
  Trap::Ptr trap;
  Result result = GetFuncExport(0)->Call(store_, {Value(1)}, results, &trap);

  ASSERT_EQ(Result::Ok, result);
  EXPECT_EQ(1u, results.size());
  EXPECT_EQ(11u, results[0].Get<u32>());
}

TEST_F(Interp2Test, HostFunc_PingPong_SameThread) {
  // (import "" "f" (func $f (param i32) (result i32)))
  // (func (export "g") (param i32) (result i32)
  //   (call $f (i32.add (local.get 0) (i32.const 1))))
  ReadModule({
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60,
      0x01, 0x7f, 0x01, 0x7f, 0x02, 0x06, 0x01, 0x00, 0x01, 0x66, 0x00, 0x00,
      0x03, 0x02, 0x01, 0x00, 0x07, 0x05, 0x01, 0x01, 0x67, 0x00, 0x01, 0x0a,
      0x0b, 0x01, 0x09, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x10, 0x00, 0x0b,
  });

  auto thread = Thread::New(store_, {});

  auto host_func = HostFunc::New(
      store_, FuncType{{ValueType::I32}, {ValueType::I32}},
      [&](const Values& params, Values& results,
          Trap::Ptr* out_trap) -> Result {
        auto val = params[0].Get<u32>();
        if (val < 10) {
          return GetFuncExport(0)->Call(*thread, {Value(val * 2)}, results,
                                        out_trap);
        }
        results[0] = Value(val);
        return Result::Ok;
      });

  Instantiate({host_func->self()});

  // Should produce the following calls:
  //  g(1) -> f(2) -> g(4) -> f(5) -> g(10) -> f(11) -> return 11

  Values results;
  Trap::Ptr trap;
  Result result = GetFuncExport(0)->Call(*thread, {Value(1)}, results, &trap);

  ASSERT_EQ(Result::Ok, result);
  EXPECT_EQ(1u, results.size());
  EXPECT_EQ(11u, results[0].Get<u32>());
}
