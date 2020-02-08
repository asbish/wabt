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

#include "src/interp2/interp2.h"

#include <algorithm>
#include <cassert>
#include <cinttypes>

#include "src/interp2/interp2-math.h"
#include "src/make-unique.h"

namespace wabt {
namespace interp2 {

const char* GetName(Mutability mut) {
  static const char* kNames[] = {"immutable", "mutable"};
  return kNames[int(mut)];
}

const char* GetName(ValueType type) {
  return GetTypeName(type);
}

const char* GetName(ExternKind kind) {
  return GetKindName(kind);
}

//// Refs ////
// static
const Ref Ref::Null{0};

//// Limits ////
Result Match(const Limits& expected,
             const Limits& actual,
             std::string* out_msg) {
  if (actual.initial < expected.initial) {
    *out_msg = StringPrintf("actual size (%" PRIu64
                            ") smaller than declared (%" PRIu64 ")",
                            actual.initial, expected.initial);
    return Result::Error;
  }

  if (expected.has_max) {
    if (!actual.has_max) {
      *out_msg = StringPrintf(
          "max size (unspecified) larger than declared (%" PRIu64 ")",
          expected.max);
      return Result::Error;
    } else if (actual.max > expected.max) {
      *out_msg = StringPrintf("max size (%" PRIu64
                              ") larger than declared (%" PRIu64 ")",
                              actual.max, expected.max);
      return Result::Error;
    }
  }

  return Result::Ok;
}

//// FuncType ////
std::unique_ptr<ExternType> FuncType::Clone() {
  return MakeUnique<FuncType>(*this);
}

Result Match(const FuncType& expected,
             const FuncType& actual,
             std::string* out_msg) {
  if (expected.params != actual.params || expected.results != actual.results) {
    if (out_msg) {
      *out_msg = "import signature mismatch";
    }
    return Result::Error;
  }
  return Result::Ok;
}

//// TableType ////
std::unique_ptr<ExternType> TableType::Clone() {
  return MakeUnique<TableType>(*this);
}

Result Match(const TableType& expected,
             const TableType& actual,
             std::string* out_msg) {
  if (expected.element != actual.element) {
    *out_msg =
        StringPrintf("type mismatch in imported table, expected %s but got %s.",
                     GetName(expected.element), GetName(actual.element));
    return Result::Error;
  }

  if (Failed(Match(expected.limits, actual.limits, out_msg))) {
    return Result::Error;
  }

  return Result::Ok;
}

//// MemoryType ////
std::unique_ptr<ExternType> MemoryType::Clone() {
  return MakeUnique<MemoryType>(*this);
}

Result Match(const MemoryType& expected,
             const MemoryType& actual,
             std::string* out_msg) {
  return Match(expected.limits, actual.limits, out_msg);
}

//// GlobalType ////
std::unique_ptr<ExternType> GlobalType::Clone() {
  return MakeUnique<GlobalType>(*this);
}

Result Match(const GlobalType& expected,
             const GlobalType& actual,
             std::string* out_msg) {
  if (actual.mut != expected.mut) {
    *out_msg = StringPrintf(
        "mutability mismatch in imported global, expected %s but got %s.",
        GetName(actual.mut), GetName(expected.mut));
    return Result::Error;
  }

  if (actual.type != expected.type &&
      (expected.mut == Mutability::Var ||
       !TypesMatch(expected.type, actual.type))) {
    *out_msg = StringPrintf(
        "type mismatch in imported global, expected %s but got %s.",
        GetName(expected.type), GetName(actual.type));
    return Result::Error;
  }

  return Result::Ok;
}

//// EventType ////
std::unique_ptr<ExternType> EventType::Clone() {
  return MakeUnique<EventType>(*this);
}

Result Match(const EventType& expected,
             const EventType& actual,
             std::string* out_msg) {
  // TODO signature
  return Result::Ok;
}

//// Limits ////
Result CanGrow(const Limits& limits, u32 old_size, u32 delta, u32* new_size) {
  if (limits.max >= delta && old_size < limits.max - delta) {
    *new_size = old_size + delta;
    return Result::Ok;
  }
  return Result::Error;
}

//// FuncDesc ////

u32 FuncDesc::GetLocalCount() const {
  return locals.empty() ? 0 : locals.back().end;
}

ValueType FuncDesc::GetLocalType(Index index) const {
  auto iter = std::lower_bound(
      locals.begin(), locals.end(), index + 1,
      [](const LocalDesc& lhs, Index rhs) { return lhs.end < rhs; });
  assert(iter != locals.end());
  return iter->type;
}

//// Store ////
Store::Store() {
  Ref ref{objects_.New(new Object(ObjectKind::Null))};
  assert(ref == Ref::Null);
  roots_.New(ref);
}

bool Store::HasValueType(Ref ref, ValueType type) const {
  // TODO opt?
  if (!IsValid(ref)) {
    return false;
  }
  if (type == ValueType::Anyref) {
    return true;
  }

  Object* obj = objects_.Get(ref.index).get();
  switch (type) {
    case ValueType::Funcref:
      return obj->kind() == ObjectKind::DefinedFunc ||
             obj->kind() == ObjectKind::HostFunc;
    case ValueType::Nullref:
      return ref.index == 0;
    case ValueType::Exnref:  // TODO
      return false;
    default:
      return false;
  }
}

Store::RootList::Index Store::NewRoot(Ref ref) {
  return roots_.New(ref);
}

Store::RootList::Index Store::CopyRoot(RootList::Index index) {
  return roots_.New(roots_.Get(index));
}

void Store::DeleteRoot(RootList::Index index) {
  roots_.Delete(index);
}

void Store::Collect() {
  std::fill(marks_.begin(), marks_.end(), false);
  Mark(roots_.list);
  for (size_t i = 0; i < marks_.size(); ++i) {
    if (!marks_[i]) {
      objects_.Delete(i);
    }
  }
}

void Store::Mark(Ref ref) {
  marks_[ref.index] = true;
}

void Store::Mark(const RefVec& refs) {
  for (auto&& ref: refs) {
    Mark(ref);
  }
}

//// Object ////
Object::~Object() {
  if (finalizer_) {
    finalizer_();
  }
}

//// Foreign ////
Foreign::Foreign(Store&, void* ptr) : Object(skind), ptr_(ptr) {}

void Foreign::Mark(Store&) {}

//// Frame ////
void Frame::Mark(Store& store) {
  store.Mark(func);
}

//// Trap ////
Trap::Trap(Store& store,
           const std::string& msg,
           const std::vector<Frame>& trace)
    : Object(skind), message_(msg), trace_(trace) {}

void Trap::Mark(Store& store) {
  for (auto&& frame : trace_) {
    frame.Mark(store);
  }
}

//// Extern ////
template <typename T>
Result Extern::MatchImpl(Store& store,
                         const ImportType& import_type,
                         const T& actual,
                         Trap::Ptr* out_trap) {
  const T* extern_type = dyn_cast<T>(import_type.type.get());
  if (!extern_type) {
    *out_trap = Trap::New(
        store,
        StringPrintf("expected import \"%s.%s\" to have kind %s, not %s",
                     import_type.module.c_str(), import_type.name.c_str(),
                     GetName(import_type.type->kind), GetName(T::skind)));
    return Result::Error;
  }

  std::string msg;
  if (Failed(interp2::Match(*extern_type, actual, &msg))) {
    *out_trap = Trap::New(store, msg);
    return Result::Error;
  }

  return Result::Ok;
}

//// Func ////
Func::Func(ObjectKind kind, FuncType type) : Extern(kind), type_(type) {}

Result Func::Call(Store& store,
                  const Values& params,
                  Values& results,
                  Trap::Ptr* out_trap,
                  Stream* trace_stream) {
  Thread::Options options;
  options.trace_stream = trace_stream;
  Thread::Ptr thread = Thread::New(store, options);
  return DoCall(*thread, params, results, out_trap);
}

Result Func::Call(Thread& thread,
                  const Values& params,
                  Values& results,
                  Trap::Ptr* out_trap) {
  return DoCall(thread, params, results, out_trap);
}

//// DefinedFunc ////
DefinedFunc::DefinedFunc(Store& store, Ref instance, FuncDesc desc)
    : Func(skind, desc.type), instance_(instance), desc_(desc) {}

void DefinedFunc::Mark(Store& store) {
  store.Mark(instance_);
}

Result DefinedFunc::Match(Store& store,
                          const ImportType& import_type,
                          Trap::Ptr* out_trap) {
  return MatchImpl(store, import_type, type_, out_trap);
}

Result DefinedFunc::DoCall(Thread& thread,
                           const Values& params,
                           Values& results,
                           Trap::Ptr* out_trap) {
  assert(params.size() == type_.params.size());
  thread.PushValues(type_.params, params);
  thread.PushCall(*this);
  RunResult result = thread.Run(out_trap);
  if (result == RunResult::Trap) {
    return Result::Error;
  }
  thread.PopValues(type_.results, &results);
  return Result::Ok;
}

//// HostFunc ////
HostFunc::HostFunc(Store&, FuncType type, Callback callback)
    : Func(skind, type), callback_(callback) {}

void HostFunc::Mark(Store&) {}

Result HostFunc::Match(Store& store,
                       const ImportType& import_type,
                       Trap::Ptr* out_trap) {
  return MatchImpl(store, import_type, type_, out_trap);
}

Result HostFunc::DoCall(Thread& thread,
                        const Values& params,
                        Values& results,
                        Trap::Ptr* out_trap) {
  return callback_(params, results, out_trap);
}

//// Table ////
Table::Table(Store&, TableDesc desc) : Extern(skind), desc_(desc) {
  elements_.resize(desc.type.limits.initial);
}

void Table::Mark(Store& store) {
  store.Mark(elements_);
}

Result Table::Match(Store& store,
                    const ImportType& import_type,
                    Trap::Ptr* out_trap) {
  return MatchImpl(store, import_type, desc_.type, out_trap);
}

bool Table::IsValidRange(u32 offset, u32 size) const {
  size_t elem_size = elements_.size();
  return size <= elem_size && offset <= elem_size - size;
}

Result Table::Get(u32 offset, Ref* out) const {
  if (IsValidRange(offset, 1)) {
    *out = elements_[offset];
    return Result::Ok;
  }
  return Result::Error;
}

Ref Table::UnsafeGet(u32 offset) const {
  assert(IsValidRange(offset, 1));
  return elements_[offset];
}

Result Table::Set(Store& store, u32 offset, Ref ref) {
  if (IsValidRange(offset, 1) && store.HasValueType(ref, desc_.type.element)) {
    elements_[offset] = ref;
    return Result::Ok;
  }
  return Result::Error;
}

Result Table::Grow(Store& store, u32 count, Ref ref) {
  size_t old_size = elements_.size();
  u32 new_size;
  if (store.HasValueType(ref, desc_.type.element) &&
      CanGrow(desc_.type.limits, old_size, count, &new_size)) {
    elements_.resize(new_size);
    Fill(store, old_size, ref, new_size - old_size);
    return Result::Ok;
  }
  return Result::Error;
}

Result Table::Fill(Store& store, u32 offset, Ref ref, u32 size) {
  if (IsValidRange(offset, size) &&
      store.HasValueType(ref, desc_.type.element)) {
    std::fill(elements_.begin() + offset, elements_.begin() + offset + size,
              ref);
    return Result::Ok;
  }
  return Result::Error;
}

Result Table::Init(Store& store,
                   u32 dst_offset,
                   const ElemSegment& src,
                   u32 src_offset,
                   u32 size) {
  if (IsValidRange(dst_offset, size) && src.IsValidRange(src_offset, size) &&
      TypesMatch(desc_.type.element, src.desc().type)) {
    std::copy(src.elements().begin() + src_offset,
              src.elements().begin() + src_offset + size,
              elements_.begin() + dst_offset);
    return Result::Ok;
  }
  return Result::Error;
}

// static
Result Table::Copy(Store& store,
                   Table& dst,
                   u32 dst_offset,
                   const Table& src,
                   u32 src_offset,
                   u32 size) {
  if (dst.IsValidRange(dst_offset, size) &&
      src.IsValidRange(src_offset, size) &&
      TypesMatch(dst.desc_.type.element, src.desc_.type.element)) {
    std::move(src.elements_.begin() + src_offset,
              src.elements_.begin() + src_offset + size,
              dst.elements_.begin() + dst_offset);
    return Result::Ok;
  }
  return Result::Error;
}

//// Memory ////
Memory::Memory(class Store&, MemoryDesc desc)
    : Extern(skind),
      desc_(desc),
      pages_(desc.type.limits.initial) {
  data_.resize(pages_ * WABT_PAGE_SIZE);
}

void Memory::Mark(class Store&) {}

Result Memory::Match(class Store& store,
                     const ImportType& import_type,
                     Trap::Ptr* out_trap) {
  return MatchImpl(store, import_type, desc_.type, out_trap);
}

Result Memory::Grow(u32 count) {
  u32 new_pages;
  if (CanGrow(desc_.type.limits, pages_, count, &new_pages)) {
    pages_ = new_pages;
    data_.resize(new_pages * WABT_PAGE_SIZE);
    return Result::Ok;
  }
  return Result::Error;
}

Result Memory::Fill(u32 offset, u8 value, u32 size) {
  if (IsValidAccess(offset, 0, size)) {
    std::fill(data_.begin() + offset, data_.begin() + offset + size, value);
    return Result::Ok;
  }
  return Result::Error;
}

Result Memory::Init(u32 dst_offset,
                    const DataSegment& src,
                    u32 src_offset,
                    u32 size) {
  if (IsValidAccess(dst_offset, 0, size) &&
      src.IsValidRange(src_offset, size)) {
    std::copy(src.desc().data.begin() + src_offset,
              src.desc().data.begin() + src_offset + size,
              data_.begin() + dst_offset);
    return Result::Ok;
  }
  return Result::Error;
}

// static
Result Memory::Copy(Memory& dst,
                    u32 dst_offset,
                    const Memory& src,
                    u32 src_offset,
                    u32 size) {
  if (dst.IsValidAccess(dst_offset, 0, size) &&
      src.IsValidAccess(src_offset, 0, size)) {
    std::move(src.data_.begin() + src_offset,
              src.data_.begin() + src_offset + size,
              dst.data_.begin() + dst_offset);
    return Result::Ok;
  }
  return Result::Error;
}

Value Instance::ResolveInitExpr(Store& store, InitExpr init) {
  Value result;
  switch (init.kind) {
    case InitExprKind::I32:      result.Set(init.i32_); break;
    case InitExprKind::I64:      result.Set(init.i64_); break;
    case InitExprKind::F32:      result.Set(init.f32_); break;
    case InitExprKind::F64:      result.Set(init.f64_); break;
    case InitExprKind::V128:     result.Set(init.v128_); break;
    case InitExprKind::GlobalGet: {
      Global::Ptr global{store, globals_[init.index_]};
      result = global->Get();
      break;
    }
    case InitExprKind::RefFunc: {
      result.Set(funcs_[init.index_]);
      break;
    }
    case InitExprKind::RefNull:
      result.Set(Ref::Null);
      break;
  }
  return result;
}

//// Global ////
Global::Global(Store& store, GlobalDesc desc, Value value)
    : Extern(skind), desc_(desc), value_(value) {}

void Global::Mark(Store& store) {
  if (IsReference(desc_.type.type)) {
    store.Mark(value_.ref_);
  }
}

Result Global::Match(Store& store,
                     const ImportType& import_type,
                     Trap::Ptr* out_trap) {
  return MatchImpl(store, import_type, desc_.type, out_trap);
}

Result Global::Set(Store& store, Ref ref) {
  if (store.HasValueType(ref, desc_.type.type)) {
    value_.Set(ref);
    return Result::Ok;
  }
  return Result::Error;
}

void Global::UnsafeSet(Value value) {
  value_ = value;
}

//// Event ////
Event::Event(Store&, EventDesc desc) : Extern(skind), desc_(desc) {}

void Event::Mark(Store&) {}

Result Event::Match(Store& store,
                    const ImportType& import_type,
                    Trap::Ptr* out_trap) {
  return MatchImpl(store, import_type, desc_.type, out_trap);
}

//// ElemSegment ////
ElemSegment::ElemSegment(const ElemDesc* desc, Instance::Ptr& inst)
    : desc_(desc) {
  elements_.reserve(desc->elements.size());
  for (auto&& elem_expr : desc->elements) {
    switch (elem_expr.kind) {
      case ElemKind::RefNull:
        elements_.emplace_back(Ref::Null);
        break;

      case ElemKind::RefFunc:
        elements_.emplace_back(inst->funcs_[elem_expr.index]);
        break;
    }
  }
}

bool ElemSegment::IsValidRange(u32 offset, u32 size) const {
  u32 elem_size = this->size();
  return size <= elem_size && offset <= elem_size - size;
}

//// DataSegment ////
DataSegment::DataSegment(const DataDesc* desc)
    : desc_(desc), size_(desc->data.size()) {}

bool DataSegment::IsValidRange(u32 offset, u32 size) const {
  u32 data_size = size_;
  return size <= data_size && offset <= data_size - size;
}

//// Module ////
Module::Module(Store&, ModuleDesc desc)
    : Object(skind), desc_(std::move(desc)) {
  for (auto&& import: desc_.imports) {
    import_types_.emplace_back(import.type);
  }

  for (auto&& export_: desc_.exports) {
    export_types_.emplace_back(export_.type);
  }
}

void Module::Mark(Store&) {}

//// ElemSegment ////
void ElemSegment::Mark(Store& store) {
  store.Mark(elements_);
}

//// Instance ////
Instance::Instance(Store& store, Ref module) : Object(skind), module_(module) {
  assert(store.Is<Module>(module));
}

// static
Instance::Ptr Instance::Instantiate(Store& store,
                                    Ref module,
                                    const RefVec& imports,
                                    Trap::Ptr* out_trap) {
  Module::Ptr mod{store, module};
  Instance::Ptr inst = store.Alloc<Instance>(store, module);

  size_t import_desc_count = mod->desc().imports.size();
  if (imports.size() > import_desc_count) {
    *out_trap = Trap::New(store, "not enough imports!");
    return {};
  }

  // Imports.
  for (size_t i = 0; i < import_desc_count; ++i) {
    auto&& import_desc = mod->desc().imports[i];
    Ref extern_ref = imports[i];
    Extern::Ptr extern_{store, extern_ref};
    if (Failed(extern_->Match(store, import_desc.type, out_trap))) {
      return {};
    }

    inst->imports_.push_back(extern_ref);

    switch (import_desc.type.type->kind) {
      case ExternKind::Func:   inst->funcs_.push_back(extern_ref); break;
      case ExternKind::Table:  inst->tables_.push_back(extern_ref); break;
      case ExternKind::Memory: inst->memories_.push_back(extern_ref); break;
      case ExternKind::Global: inst->globals_.push_back(extern_ref); break;
      case ExternKind::Event:  inst->events_.push_back(extern_ref); break;
    }
  }

  // Funcs.
  for (auto&& desc : mod->desc().funcs) {
    inst->funcs_.push_back(DefinedFunc::New(store, inst.ref(), desc).ref());
  }

  // Tables.
  for (auto&& desc : mod->desc().tables) {
    inst->tables_.push_back(Table::New(store, desc).ref());
  }

  // Memories.
  for (auto&& desc : mod->desc().memories) {
    inst->memories_.push_back(Memory::New(store, desc).ref());
  }

  // Globals.
  for (auto&& desc : mod->desc().globals) {
    inst->globals_.push_back(
        Global::New(store, desc, inst->ResolveInitExpr(store, desc.init))
            .ref());
  }

  // Events.
  for (auto&& desc : mod->desc().events) {
    inst->events_.push_back(Event::New(store, desc).ref());
  }

  // Exports.
  for (auto&& desc : mod->desc().exports){
    Ref ref;
    switch (desc.type.type->kind) {
      case ExternKind::Func:   ref = inst->funcs_[desc.index]; break;
      case ExternKind::Table:  ref = inst->tables_[desc.index]; break;
      case ExternKind::Memory: ref = inst->memories_[desc.index]; break;
      case ExternKind::Global: ref = inst->globals_[desc.index]; break;
      case ExternKind::Event:  ref = inst->events_[desc.index]; break;
    }
    inst->exports_.push_back(ref);
  }

  // Elems.
  for (auto&& desc : mod->desc().elems) {
    inst->elems_.emplace_back(&desc, inst);
  }

  // Datas.
  for (auto&& desc : mod->desc().datas) {
    inst->datas_.emplace_back(&desc);
  }

  // Initialization.
  enum Pass { Check, Init };
  for (auto pass : {Check, Init}) {
    // Elems.
    for (auto&& segment : inst->elems_) {
      auto&& desc = segment.desc();
      if (desc.mode == SegmentMode::Active) {
        Result result;
        Table::Ptr table{store, inst->tables_[desc.table_index]};
        u32 offset = inst->ResolveInitExpr(store, desc.offset).Get<u32>();
        if (pass == Check) {
          result = table->IsValidRange(offset, segment.size()) ? Result::Ok
                                                               : Result::Error;
        } else {
          result = table->Init(store, offset, segment, 0, segment.size());
          segment.Drop();
        }

        if (Failed(result)) {
          *out_trap = Trap::New(store, "table.init out of bounds");
          return {};
        }
      }
    }

    // Data.
    for (auto&& segment : inst->datas_) {
      auto&& desc = segment.desc();
      if (desc.mode == SegmentMode::Active) {
        Result result;
        Memory::Ptr memory{store, inst->tables_[desc.memory_index]};
        u32 offset = inst->ResolveInitExpr(store, desc.offset).Get<u32>();
        if (pass == Check) {
          result = memory->IsValidAccess(offset, 0, segment.size())
                       ? Result::Ok
                       : Result::Error;
        } else {
          result = memory->Init(offset, segment, 0, segment.size());
          segment.Drop();
        }

        if (Failed(result)) {
          *out_trap = Trap::New(store, "memory.init out of bounds");
          return {};
        }
      }
    }
  }

  // Start.
  for (auto&& start : mod->desc().starts) {
    Func::Ptr func{store, inst->funcs_[start.func_index]};
    Values results;
    if (Failed(func->Call(store, {}, results, out_trap))) {
      return {};
    }
  }

  return inst;
}

void Instance::Mark(Store& store) {
  store.Mark(module_);
  store.Mark(imports_);
  store.Mark(funcs_);
  store.Mark(memories_);
  store.Mark(tables_);
  store.Mark(globals_);
  store.Mark(events_);
  store.Mark(exports_);
  for (auto&& elem : elems_) {
    elem.Mark(store);
  }
}

//// Thread ////
Thread::Thread(Store& store, const Options& options)
    : Object(skind), store_(store) {
  frames_.reserve(options.call_stack_size);
  values_.reserve(options.value_stack_size);
  trace_stream_ = options.trace_stream;
  if (options.trace_stream) {
    trace_source_ = new TraceSource(this);
  }
}

void Thread::Mark(Store& store) {
  for (auto&& frame : frames_) {
    frame.Mark(store);
  }
  for (auto index: refs_) {
    store.Mark(values_[index].ref_);
  }
}

void Thread::PushValues(const ValueTypes& types, const Values& values) {
  assert(types.size() == values.size());
  for (size_t i = 0; i < types.size(); ++i) {
    if (IsReference(types[i])) {
      refs_.push_back(values_.size());
    }
    values_.push_back(values[i]);
  }
}

void Thread::PushCall(Ref func, u32 offset) {
  frames_.emplace_back(func, values_.size(), offset, inst_, mod_);
}

void Thread::PushCall(const DefinedFunc& func) {
  inst_ = store_.UnsafeGet<Instance>(func.instance()).get();
  mod_ = store_.UnsafeGet<Module>(inst_->module()).get();
  frames_.emplace_back(func.self(), values_.size(), func.desc().code_offset,
                       inst_, mod_);
}

void Thread::PushCall(const HostFunc& func) {
  inst_ = nullptr;
  mod_ = nullptr;
  frames_.emplace_back(func.self(), values_.size(), 0, inst_, mod_);
}

RunResult Thread::PopCall() {
  frames_.pop_back();
  if (frames_.empty()) {
    return RunResult::Return;
  }

  auto& frame = frames_.back();
  if (!frame.inst) {
    // Returning to a HostFunc called on this thread.
    return RunResult::Return;
  }

  inst_ = frame.inst;
  mod_ = frame.mod;
  return RunResult::Ok;
}

RunResult Thread::DoReturnCall(const Func::Ptr& func, Trap::Ptr* out_trap) {
  // TODO
  return RunResult::Ok;
}

void Thread::PopValues(const ValueTypes& types, Values* out_values) {
  assert(values_.size() >= types.size());
  out_values->resize(types.size());
  std::copy(values_.end() - types.size(), values_.end(), out_values->begin());
  values_.resize(values_.size() - types.size());
}

RunResult Thread::Run(Trap::Ptr* out_trap) {
  const int kDefaultInstructionCount = 1000;
  RunResult result;
  do {
    result = Run(kDefaultInstructionCount, out_trap);
  } while (result == RunResult::Ok);
  return result;
}

RunResult Thread::Run(int num_instructions, Trap::Ptr* out_trap) {
  DefinedFunc::Ptr func{store_, frames_.back().func};
  for (;num_instructions > 0; --num_instructions) {
    auto result = StepInternal(out_trap);
    if (result != RunResult::Ok) {
      return result;
    }
  }
  return RunResult::Ok;
}

RunResult Thread::Step(Trap::Ptr* out_trap) {
  DefinedFunc::Ptr func{store_, frames_.back().func};
  return StepInternal(out_trap);
}

Value& Thread::Pick(Index index) {
  assert(index > 0 && index <= values_.size());
  return values_[values_.size() - index];
}

template <typename T>
T Thread::Pop() {
  return Pop().Get<T>();
}

Value Thread::Pop() {
  if (!refs_.empty() && refs_.back() >= values_.size()) {
    refs_.pop_back();
  }
  auto value = values_.back();
  values_.pop_back();
  return value;
}

template <typename T>
void Thread::Push(T value) {
  Push(Value(value));
}

template <>
void Thread::Push<bool>(bool value) {
  Push(Value(static_cast<u32>(value ? 1 : 0)));
}

void Thread::Push(Value value) {
  values_.push_back(value);
}

void Thread::Push(Ref ref) {
  refs_.push_back(values_.size());
  values_.push_back(Value(ref));
}

#define TRAP(msg) *out_trap = Trap::New(store_, (msg), frames_), RunResult::Trap
#define TRAP_IF(cond, msg)     \
  if (WABT_UNLIKELY((cond))) { \
    return TRAP(msg);          \
  }
#define TRAP_UNLESS(cond, msg) TRAP_IF(!(cond), msg)

RunResult Thread::StepInternal(Trap::Ptr* out_trap) {
  using O = Opcode;

  u32& pc = frames_.back().offset;
  auto& istream = mod_->desc().istream;

  if (trace_stream_) {
    istream.Trace(trace_stream_, pc, trace_source_);
  }

  auto instr = istream.Read(&pc);
  switch (instr.op) {
    case O::Unreachable:
      return TRAP("unreachable executed");

    case O::Br:
      pc = instr.imm_u32;
      break;

    case O::BrIf:
      if (Pop<u32>()) {
        pc = instr.imm_u32;
      }
      break;

    case O::BrTable: {
      auto key = Pop<u32>();
      if (key >= instr.imm_u32) {
        key = instr.imm_u32;
      }
      pc += key * 16;  // TODO: magic number
      break;
    }

    case O::Return:
      return PopCall();

    case O::Call: {
      Ref new_func_ref = inst_->funcs()[instr.imm_u32];
      DefinedFunc::Ptr new_func{store_, new_func_ref};
      PushCall(new_func_ref, new_func->desc().code_offset);
      break;
    }

    case O::CallIndirect:
    case O::ReturnCallIndirect: {
      Table::Ptr table{store_, inst_->tables()[instr.imm_u32x2.fst]};
      auto&& func_type = mod_->desc().func_types[instr.imm_u32x2.snd];
      auto entry = Pop<u32>();
      TRAP_IF(entry >= table->elements().size(), "undefined table index");
      auto new_func_ref = table->elements()[entry];
      TRAP_IF(new_func_ref == Ref::Null, "uninitialized table element");
      Func::Ptr new_func{store_, new_func_ref};
      TRAP_IF(Failed(Match(new_func->func_type(), func_type, nullptr)),
              "call indirect func type mismatch");
      if (instr.op == O::ReturnCallIndirect) {
        return DoReturnCall(new_func, out_trap);
      } else {
        return DoCall(new_func, out_trap);
      }
    }

    case O::Drop:
      Pop();
      break;

    case O::Select: {
      auto cond = Pop<u32>();
      Value false_ = Pop();
      Value true_ = Pop();
      Push(cond ? true_ : false_);
      break;
    }

    case O::LocalGet:
      // TODO: need to mark whether this is a ref.
      Push(Pick(instr.imm_u32));
      break;

    case O::LocalSet: {
      auto value = Pop();
      Pick(instr.imm_u32) = value;
      break;
    }

    case O::LocalTee:
      Pick(instr.imm_u32) = Pick(1);
      break;

    case O::GlobalGet: {
      // TODO: need to mark whether this is a ref.
      Global::Ptr global{store_, inst_->globals()[instr.imm_u32]};
      Push(global->Get());
      break;
    }

    case O::GlobalSet: {
      Global::Ptr global{store_, inst_->globals()[instr.imm_u32]};
      global->UnsafeSet(Pop());
      break;
    }

    case O::I32Load:    return DoLoad<u32>(instr, out_trap);
    case O::I64Load:    return DoLoad<u64>(instr, out_trap);
    case O::F32Load:    return DoLoad<f32>(instr, out_trap);
    case O::F64Load:    return DoLoad<f64>(instr, out_trap);
    case O::I32Load8S:  return DoLoad<s8, s32>(instr, out_trap);
    case O::I32Load8U:  return DoLoad<u8, u32>(instr, out_trap);
    case O::I32Load16S: return DoLoad<s16, s32>(instr, out_trap);
    case O::I32Load16U: return DoLoad<u16, u32>(instr, out_trap);
    case O::I64Load8S:  return DoLoad<s8, s64>(instr, out_trap);
    case O::I64Load8U:  return DoLoad<u8, u64>(instr, out_trap);
    case O::I64Load16S: return DoLoad<s16, s64>(instr, out_trap);
    case O::I64Load16U: return DoLoad<u16, u64>(instr, out_trap);
    case O::I64Load32S: return DoLoad<s32, s64>(instr, out_trap);
    case O::I64Load32U: return DoLoad<u32, u64>(instr, out_trap);

    case O::I32Store:   return DoStore<u32>(instr, out_trap);
    case O::I64Store:   return DoStore<u64>(instr, out_trap);
    case O::F32Store:   return DoStore<f32>(instr, out_trap);
    case O::F64Store:   return DoStore<f64>(instr, out_trap);
    case O::I32Store8:  return DoStore<u8, u32>(instr, out_trap);
    case O::I32Store16: return DoStore<u16, u32>(instr, out_trap);
    case O::I64Store8:  return DoStore<u8, u64>(instr, out_trap);
    case O::I64Store16: return DoStore<u16, u64>(instr, out_trap);
    case O::I64Store32: return DoStore<u32, u64>(instr, out_trap);

    case O::MemorySize: {
      Memory::Ptr memory{store_, inst_->memories()[instr.imm_u32]};
      Push(memory->PageSize());
      break;
    }

    case O::MemoryGrow: {
      Memory::Ptr memory{store_, inst_->memories()[instr.imm_u32]};
      u32 old_size = memory->PageSize();
      if (Failed(memory->Grow(Pop<u32>()))) {
        Push<s32>(-1);
      } else {
        Push<u32>(old_size);
      }
      break;
    }

    case O::I32Const: Push(instr.imm_u32); break;
    case O::F32Const: Push(instr.imm_f32); break;
    case O::I64Const: Push(instr.imm_u64); break;
    case O::F64Const: Push(instr.imm_f64); break;

    case O::I32Eqz: return DoUnop(IntEqz<u32>);
    case O::I32Eq:  return DoBinop(Eq<u32>);
    case O::I32Ne:  return DoBinop(Ne<u32>);
    case O::I32LtS: return DoBinop(Lt<s32>);
    case O::I32LtU: return DoBinop(Lt<u32>);
    case O::I32GtS: return DoBinop(Gt<s32>);
    case O::I32GtU: return DoBinop(Gt<u32>);
    case O::I32LeS: return DoBinop(Le<s32>);
    case O::I32LeU: return DoBinop(Le<u32>);
    case O::I32GeS: return DoBinop(Ge<s32>);
    case O::I32GeU: return DoBinop(Ge<u32>);

    case O::I64Eqz: return DoUnop(IntEqz<u64>);
    case O::I64Eq:  return DoBinop(Eq<u64>);
    case O::I64Ne:  return DoBinop(Ne<u64>);
    case O::I64LtS: return DoBinop(Lt<s64>);
    case O::I64LtU: return DoBinop(Lt<u64>);
    case O::I64GtS: return DoBinop(Gt<s64>);
    case O::I64GtU: return DoBinop(Gt<u64>);
    case O::I64LeS: return DoBinop(Le<s64>);
    case O::I64LeU: return DoBinop(Le<u64>);
    case O::I64GeS: return DoBinop(Ge<s64>);
    case O::I64GeU: return DoBinop(Ge<u64>);

    case O::F32Eq:  return DoBinop(Eq<f32>);
    case O::F32Ne:  return DoBinop(Ne<f32>);
    case O::F32Lt:  return DoBinop(Lt<f32>);
    case O::F32Gt:  return DoBinop(Gt<f32>);
    case O::F32Le:  return DoBinop(Le<f32>);
    case O::F32Ge:  return DoBinop(Ge<f32>);

    case O::F64Eq:  return DoBinop(Eq<f64>);
    case O::F64Ne:  return DoBinop(Ne<f64>);
    case O::F64Lt:  return DoBinop(Lt<f64>);
    case O::F64Gt:  return DoBinop(Gt<f64>);
    case O::F64Le:  return DoBinop(Le<f64>);
    case O::F64Ge:  return DoBinop(Ge<f64>);

    case O::I32Clz:    return DoUnop(IntClz<u32>);
    case O::I32Ctz:    return DoUnop(IntCtz<u32>);
    case O::I32Popcnt: return DoUnop(IntPopcnt<u32>);
    case O::I32Add:    return DoBinop(Add<u32>);
    case O::I32Sub:    return DoBinop(Sub<u32>);
    case O::I32Mul:    return DoBinop(Mul<u32>);
    case O::I32DivS:   return DoBinop(IntDiv<s32>, out_trap);
    case O::I32DivU:   return DoBinop(IntDiv<u32>, out_trap);
    case O::I32RemS:   return DoBinop(IntRem<s32>, out_trap);
    case O::I32RemU:   return DoBinop(IntRem<u32>, out_trap);
    case O::I32And:    return DoBinop(IntAnd<u32>);
    case O::I32Or:     return DoBinop(IntOr<u32>);
    case O::I32Xor:    return DoBinop(IntXor<u32>);
    case O::I32Shl:    return DoBinop(IntShl<u32>);
    case O::I32ShrS:   return DoBinop(IntShr<s32>);
    case O::I32ShrU:   return DoBinop(IntShr<u32>);
    case O::I32Rotl:   return DoBinop(IntRotl<u32>);
    case O::I32Rotr:   return DoBinop(IntRotr<u32>);

    case O::I64Clz:    return DoUnop(IntClz<u64>);
    case O::I64Ctz:    return DoUnop(IntCtz<u64>);
    case O::I64Popcnt: return DoUnop(IntPopcnt<u64>);
    case O::I64Add:    return DoBinop(Add<u64>);
    case O::I64Sub:    return DoBinop(Sub<u64>);
    case O::I64Mul:    return DoBinop(Mul<u64>);
    case O::I64DivS:   return DoBinop(IntDiv<s64>, out_trap);
    case O::I64DivU:   return DoBinop(IntDiv<u64>, out_trap);
    case O::I64RemS:   return DoBinop(IntRem<s64>, out_trap);
    case O::I64RemU:   return DoBinop(IntRem<u64>, out_trap);
    case O::I64And:    return DoBinop(IntAnd<u64>);
    case O::I64Or:     return DoBinop(IntOr<u64>);
    case O::I64Xor:    return DoBinop(IntXor<u64>);
    case O::I64Shl:    return DoBinop(IntShl<u64>);
    case O::I64ShrS:   return DoBinop(IntShr<s64>);
    case O::I64ShrU:   return DoBinop(IntShr<u64>);
    case O::I64Rotl:   return DoBinop(IntRotl<u64>);
    case O::I64Rotr:   return DoBinop(IntRotr<u64>);

    case O::F32Abs:     return DoUnop(FloatAbs<f32>);
    case O::F32Neg:     return DoUnop(Neg<f32>);
    case O::F32Ceil:    return DoUnop(FloatCeil<f32>);
    case O::F32Floor:   return DoUnop(FloatFloor<f32>);
    case O::F32Trunc:   return DoUnop(FloatTrunc<f32>);
    case O::F32Nearest: return DoUnop(FloatNearest<f32>);
    case O::F32Sqrt:    return DoUnop(FloatSqrt<f32>);
    case O::F32Add:      return DoBinop(Add<f32>);
    case O::F32Sub:      return DoBinop(Sub<f32>);
    case O::F32Mul:      return DoBinop(Mul<f32>);
    case O::F32Div:      return DoBinop(FloatDiv<f32>);
    case O::F32Min:      return DoBinop(FloatMin<f32>);
    case O::F32Max:      return DoBinop(FloatMax<f32>);
    case O::F32Copysign: return DoBinop(FloatCopysign<f32>);

    case O::F64Abs:     return DoUnop(FloatAbs<f64>);
    case O::F64Neg:     return DoUnop(Neg<f64>);
    case O::F64Ceil:    return DoUnop(FloatCeil<f64>);
    case O::F64Floor:   return DoUnop(FloatFloor<f64>);
    case O::F64Trunc:   return DoUnop(FloatTrunc<f64>);
    case O::F64Nearest: return DoUnop(FloatNearest<f64>);
    case O::F64Sqrt:    return DoUnop(FloatSqrt<f64>);
    case O::F64Add:      return DoBinop(Add<f64>);
    case O::F64Sub:      return DoBinop(Sub<f64>);
    case O::F64Mul:      return DoBinop(Mul<f64>);
    case O::F64Div:      return DoBinop(FloatDiv<f64>);
    case O::F64Min:      return DoBinop(FloatMin<f64>);
    case O::F64Max:      return DoBinop(FloatMax<f64>);
    case O::F64Copysign: return DoBinop(FloatCopysign<f64>);

    case O::I32WrapI64:      return DoConvert<u32, u64>(out_trap);
    case O::I32TruncF32S:    return DoConvert<s32, f32>(out_trap);
    case O::I32TruncF32U:    return DoConvert<u32, f32>(out_trap);
    case O::I32TruncF64S:    return DoConvert<s32, f64>(out_trap);
    case O::I32TruncF64U:    return DoConvert<u32, f64>(out_trap);
    case O::I64ExtendI32S:   return DoConvert<s64, s32>(out_trap);
    case O::I64ExtendI32U:   return DoConvert<u64, u32>(out_trap);
    case O::I64TruncF32S:    return DoConvert<s64, f32>(out_trap);
    case O::I64TruncF32U:    return DoConvert<u64, f32>(out_trap);
    case O::I64TruncF64S:    return DoConvert<s64, f64>(out_trap);
    case O::I64TruncF64U:    return DoConvert<u64, f64>(out_trap);
    case O::F32ConvertI32S:  return DoConvert<f32, s32>(out_trap);
    case O::F32ConvertI32U:  return DoConvert<f32, u32>(out_trap);
    case O::F32ConvertI64S:  return DoConvert<f32, s64>(out_trap);
    case O::F32ConvertI64U:  return DoConvert<f32, u64>(out_trap);
    case O::F32DemoteF64:    return DoConvert<f32, f64>(out_trap);
    case O::F64ConvertI32S:  return DoConvert<f64, s32>(out_trap);
    case O::F64ConvertI32U:  return DoConvert<f64, u32>(out_trap);
    case O::F64ConvertI64S:  return DoConvert<f64, s64>(out_trap);
    case O::F64ConvertI64U:  return DoConvert<f64, u64>(out_trap);
    case O::F64PromoteF32:   return DoConvert<f64, f64>(out_trap);

    case O::I32ReinterpretF32: return DoReinterpret<u32, f32>();
    case O::F32ReinterpretI32: return DoReinterpret<f32, u32>();
    case O::I64ReinterpretF64: return DoReinterpret<u64, f64>();
    case O::F64ReinterpretI64: return DoReinterpret<f64, u64>();

    case O::I32Extend8S:   return DoUnop(IntExtend<u32, 7>);
    case O::I32Extend16S:  return DoUnop(IntExtend<u32, 15>);
    case O::I64Extend8S:   return DoUnop(IntExtend<u64, 7>);
    case O::I64Extend16S:  return DoUnop(IntExtend<u64, 15>);
    case O::I64Extend32S:  return DoUnop(IntExtend<u64, 31>);

    case O::InterpAlloca:
      values_.resize(values_.size() + instr.imm_u32);
      // refs_ doesn't need to be updated; We may be allocating space for
      // references, but they will be initialized to null, so it is OK if we
      // don't mark them.
      break;

    case O::InterpBrUnless:
      if (!Pop<u32>()) {
        pc = instr.imm_u32;
      }
      break;

    case O::InterpCallHost: {
      Ref new_func_ref = inst_->funcs()[instr.imm_u32];
      Func::Ptr new_func{store_, new_func_ref};
      return DoCall(new_func, out_trap);
    }

    case O::InterpDropKeep: {
      auto drop = instr.imm_u32x2.fst;
      auto keep = instr.imm_u32x2.snd;
      // Shift kept refs down.
      for (auto iter = refs_.rbegin(); iter != refs_.rend(); ++iter) {
        if (*iter >= values_.size() - keep) {
          *iter -= drop;
        } else {
          break;
        }
      }
      std::move(values_.end() - keep, values_.end(), values_.end() - drop - keep);
      values_.resize(values_.size() - drop);
      break;
    }

    case O::I32TruncSatF32S: return DoUnop(IntTruncSat<s32, f32>);
    case O::I32TruncSatF32U: return DoUnop(IntTruncSat<u32, f32>);
    case O::I32TruncSatF64S: return DoUnop(IntTruncSat<s32, f64>);
    case O::I32TruncSatF64U: return DoUnop(IntTruncSat<u32, f64>);
    case O::I64TruncSatF32S: return DoUnop(IntTruncSat<s64, f32>);
    case O::I64TruncSatF32U: return DoUnop(IntTruncSat<u64, f32>);
    case O::I64TruncSatF64S: return DoUnop(IntTruncSat<s64, f64>);
    case O::I64TruncSatF64U: return DoUnop(IntTruncSat<u64, f64>);

    case O::MemoryInit: return DoMemoryInit(instr, out_trap);
    case O::DataDrop:   return DoDataDrop(instr);
    case O::MemoryCopy: return DoMemoryCopy(instr, out_trap);
    case O::MemoryFill: return DoMemoryFill(instr, out_trap);

    case O::TableInit: return DoTableInit(instr, out_trap);
    case O::ElemDrop:  return DoElemDrop(instr);
    case O::TableCopy: return DoTableCopy(instr, out_trap);
    case O::TableGet:  return DoTableGet(instr, out_trap);
    case O::TableSet:  return DoTableSet(instr, out_trap);
    case O::TableGrow: return DoTableGrow(instr, out_trap);
    case O::TableSize: return DoTableSize(instr);
    case O::TableFill: return DoTableFill(instr, out_trap);

    case O::RefNull:
      Push(Ref::Null);
      break;

    case O::RefIsNull:
      Push(Pop<Ref>() == Ref::Null);
      break;

    case O::RefFunc:
      Push(inst_->funcs()[instr.imm_u32]);
      break;

    case O::V128Load: return DoLoad<v128>(instr, out_trap);
    case O::V128Store: return DoStore<v128>(instr, out_trap);

    case O::V128Const:
      Push<v128>(instr.imm_v128);
      break;

    case O::I8X16Splat:        return DoSimdSplat<u8x16, u32>();
    case O::I8X16ExtractLaneS: return DoSimdExtract<s8x16, s32>(instr);
    case O::I8X16ExtractLaneU: return DoSimdExtract<u8x16, u32>(instr);
    case O::I8X16ReplaceLane:  return DoSimdReplace<u8x16, u32>(instr);
    case O::I16X8Splat:        return DoSimdSplat<u16x8, u32>();
    case O::I16X8ExtractLaneS: return DoSimdExtract<s16x8, s32>(instr);
    case O::I16X8ExtractLaneU: return DoSimdExtract<u16x8, u32>(instr);
    case O::I16X8ReplaceLane:  return DoSimdReplace<u16x8, u32>(instr);
    case O::I32X4Splat:        return DoSimdSplat<u32x4, u32>();
    case O::I32X4ExtractLane:  return DoSimdExtract<s32x4, u32>(instr);
    case O::I32X4ReplaceLane:  return DoSimdReplace<u32x4, u32>(instr);
    case O::I64X2Splat:        return DoSimdSplat<u64x2, u64>();
    case O::I64X2ExtractLane:  return DoSimdExtract<u64x2, u64>(instr);
    case O::I64X2ReplaceLane:  return DoSimdReplace<u64x2, u64>(instr);
    case O::F32X4Splat:        return DoSimdSplat<f32x4, f32>();
    case O::F32X4ExtractLane:  return DoSimdExtract<f32x4, f32>(instr);
    case O::F32X4ReplaceLane:  return DoSimdReplace<f32x4, f32>(instr);
    case O::F64X2Splat:        return DoSimdSplat<f64x2, f64>();
    case O::F64X2ExtractLane:  return DoSimdExtract<f64x2, f64>(instr);
    case O::F64X2ReplaceLane:  return DoSimdReplace<f64x2, f64>(instr);

    case O::I8X16Eq:  return DoSimdBinop<u8x16>(EqMask<u8>);
    case O::I8X16Ne:  return DoSimdBinop<u8x16>(NeMask<u8>);
    case O::I8X16LtS: return DoSimdBinop<u8x16>(LtMask<s8>);
    case O::I8X16LtU: return DoSimdBinop<u8x16>(LtMask<u8>);
    case O::I8X16GtS: return DoSimdBinop<u8x16>(GtMask<s8>);
    case O::I8X16GtU: return DoSimdBinop<u8x16>(GtMask<u8>);
    case O::I8X16LeS: return DoSimdBinop<u8x16>(LeMask<s8>);
    case O::I8X16LeU: return DoSimdBinop<u8x16>(LeMask<u8>);
    case O::I8X16GeS: return DoSimdBinop<u8x16>(GeMask<s8>);
    case O::I8X16GeU: return DoSimdBinop<u8x16>(GeMask<u8>);
    case O::I16X8Eq:  return DoSimdBinop<u16x8>(EqMask<u16>);
    case O::I16X8Ne:  return DoSimdBinop<u16x8>(NeMask<u16>);
    case O::I16X8LtS: return DoSimdBinop<s16x8>(LtMask<s16>);
    case O::I16X8LtU: return DoSimdBinop<u16x8>(LtMask<u16>);
    case O::I16X8GtS: return DoSimdBinop<s16x8>(GtMask<s16>);
    case O::I16X8GtU: return DoSimdBinop<u16x8>(GtMask<u16>);
    case O::I16X8LeS: return DoSimdBinop<s16x8>(LeMask<s16>);
    case O::I16X8LeU: return DoSimdBinop<u16x8>(LeMask<u16>);
    case O::I16X8GeS: return DoSimdBinop<s16x8>(GeMask<s16>);
    case O::I16X8GeU: return DoSimdBinop<u16x8>(GeMask<u16>);
    case O::I32X4Eq:  return DoSimdBinop<u32x4>(EqMask<u32>);
    case O::I32X4Ne:  return DoSimdBinop<u32x4>(NeMask<u32>);
    case O::I32X4LtS: return DoSimdBinop<s32x4>(LtMask<s32>);
    case O::I32X4LtU: return DoSimdBinop<u32x4>(LtMask<u32>);
    case O::I32X4GtS: return DoSimdBinop<s32x4>(GtMask<s32>);
    case O::I32X4GtU: return DoSimdBinop<u32x4>(GtMask<u32>);
    case O::I32X4LeS: return DoSimdBinop<s32x4>(LeMask<s32>);
    case O::I32X4LeU: return DoSimdBinop<u32x4>(LeMask<u32>);
    case O::I32X4GeS: return DoSimdBinop<s32x4>(GeMask<s32>);
    case O::I32X4GeU: return DoSimdBinop<u32x4>(GeMask<u32>);
    case O::F32X4Eq:  return DoSimdBinop<f32x4>(EqMask<f32>);
    case O::F32X4Ne:  return DoSimdBinop<f32x4>(NeMask<f32>);
    case O::F32X4Lt:  return DoSimdBinop<f32x4>(LtMask<f32>);
    case O::F32X4Gt:  return DoSimdBinop<f32x4>(GtMask<f32>);
    case O::F32X4Le:  return DoSimdBinop<f32x4>(LeMask<f32>);
    case O::F32X4Ge:  return DoSimdBinop<f32x4>(GeMask<f32>);
    case O::F64X2Eq:  return DoSimdBinop<f64x2>(EqMask<f64>);
    case O::F64X2Ne:  return DoSimdBinop<f64x2>(NeMask<f64>);
    case O::F64X2Lt:  return DoSimdBinop<f64x2>(LtMask<f64>);
    case O::F64X2Gt:  return DoSimdBinop<f64x2>(GtMask<f64>);
    case O::F64X2Le:  return DoSimdBinop<f64x2>(LeMask<f64>);
    case O::F64X2Ge:  return DoSimdBinop<f64x2>(GeMask<f64>);

    case O::V128Not:       return DoSimdUnop<u64x2>(IntNot<u64>);
    case O::V128And:       return DoSimdBinop<u64x2>(IntAnd<u64>);
    case O::V128Or:        return DoSimdBinop<u64x2>(IntOr<u64>);
    case O::V128Xor:       return DoSimdBinop<u64x2>(IntXor<u64>);
    case O::V128BitSelect: return DoSimdBitSelect();

    case O::I8X16Neg:          return DoSimdUnop<u8x16>(Neg<u8>);
    case O::I8X16AnyTrue:      return DoSimdIsTrue<u8x16, 1>();
    case O::I8X16AllTrue:      return DoSimdIsTrue<u8x16, 16>();
    case O::I8X16Shl:          return DoSimdShift<u8x16>(IntShl<u8>);
    case O::I8X16ShrS:         return DoSimdShift<u8x16>(IntShr<s8>);
    case O::I8X16ShrU:         return DoSimdShift<u8x16>(IntShr<u8>);
    case O::I8X16Add:          return DoSimdBinop<u8x16>(Add<u8>);
    case O::I8X16AddSaturateS: return DoSimdBinop<u8x16>(IntAddSat<s8>);
    case O::I8X16AddSaturateU: return DoSimdBinop<u8x16>(IntAddSat<u8>);
    case O::I8X16Sub:          return DoSimdBinop<u8x16>(Sub<u8>);
    case O::I8X16SubSaturateS: return DoSimdBinop<u8x16>(IntSubSat<s8>);
    case O::I8X16SubSaturateU: return DoSimdBinop<u8x16>(IntSubSat<u8>);

    case O::I16X8Neg:          return DoSimdUnop<u16x8>(Neg<u16>);
    case O::I16X8AnyTrue:      return DoSimdIsTrue<u16x8, 1>();
    case O::I16X8AllTrue:      return DoSimdIsTrue<u16x8, 8>();
    case O::I16X8Shl:          return DoSimdShift<u16x8>(IntShl<u16>);
    case O::I16X8ShrS:         return DoSimdShift<u16x8>(IntShr<s16>);
    case O::I16X8ShrU:         return DoSimdShift<u16x8>(IntShr<u16>);
    case O::I16X8Add:          return DoSimdBinop<u16x8>(Add<u16>);
    case O::I16X8AddSaturateS: return DoSimdBinop<u16x8>(IntAddSat<s16>);
    case O::I16X8AddSaturateU: return DoSimdBinop<u16x8>(IntAddSat<u16>);
    case O::I16X8Sub:          return DoSimdBinop<u16x8>(Sub<u16>);
    case O::I16X8SubSaturateS: return DoSimdBinop<u16x8>(IntSubSat<s16>);
    case O::I16X8SubSaturateU: return DoSimdBinop<u16x8>(IntSubSat<u16>);
    case O::I16X8Mul:          return DoSimdBinop<u16x8>(Mul<u16>);

    case O::I32X4Neg:          return DoSimdUnop<u32x4>(Neg<u32>);
    case O::I32X4AnyTrue:      return DoSimdIsTrue<u32x4, 1>();
    case O::I32X4AllTrue:      return DoSimdIsTrue<u32x4, 4>();
    case O::I32X4Shl:          return DoSimdShift<u32x4>(IntShl<u32>);
    case O::I32X4ShrS:         return DoSimdShift<u32x4>(IntShr<s32>);
    case O::I32X4ShrU:         return DoSimdShift<u32x4>(IntShr<u32>);
    case O::I32X4Add:          return DoSimdBinop<u32x4>(Add<u32>);
    case O::I32X4Sub:          return DoSimdBinop<u32x4>(Sub<u32>);
    case O::I32X4Mul:          return DoSimdBinop<u32x4>(Mul<u32>);

    case O::I64X2Neg:          return DoSimdUnop<u64x2>(Neg<u64>);
    case O::I64X2Shl:          return DoSimdShift<u64x2>(IntShl<u64>);
    case O::I64X2ShrS:         return DoSimdShift<u64x2>(IntShr<s64>);
    case O::I64X2ShrU:         return DoSimdShift<u64x2>(IntShr<u64>);
    case O::I64X2Add:          return DoSimdBinop<u64x2>(Add<u64>);
    case O::I64X2Sub:          return DoSimdBinop<u64x2>(Sub<u64>);

    case O::F32X4Abs:          return DoSimdUnop<f32x4>(FloatAbs<f32>);
    case O::F32X4Neg:          return DoSimdUnop<f32x4>(Neg<f32>);
    case O::F32X4Sqrt:         return DoSimdUnop<f32x4>(FloatSqrt<f32>);
    case O::F32X4Add:          return DoSimdBinop<f32x4>(Add<f32>);
    case O::F32X4Sub:          return DoSimdBinop<f32x4>(Sub<f32>);
    case O::F32X4Mul:          return DoSimdBinop<f32x4>(Mul<f32>);
    case O::F32X4Div:          return DoSimdBinop<f32x4>(FloatDiv<f32>);
    case O::F32X4Min:          return DoSimdBinop<f32x4>(FloatMin<f32>);
    case O::F32X4Max:          return DoSimdBinop<f32x4>(FloatMax<f32>);

    case O::F64X2Abs:          return DoSimdUnop<f64x2>(FloatAbs<f64>);
    case O::F64X2Neg:          return DoSimdUnop<f64x2>(Neg<f64>);
    case O::F64X2Sqrt:         return DoSimdUnop<f64x2>(FloatSqrt<f64>);
    case O::F64X2Add:          return DoSimdBinop<f64x2>(Add<f64>);
    case O::F64X2Sub:          return DoSimdBinop<f64x2>(Sub<f64>);
    case O::F64X2Mul:          return DoSimdBinop<f64x2>(Mul<f64>);
    case O::F64X2Div:          return DoSimdBinop<f64x2>(FloatDiv<f64>);
    case O::F64X2Min:          return DoSimdBinop<f64x2>(FloatMin<f64>);
    case O::F64X2Max:          return DoSimdBinop<f64x2>(FloatMax<f64>);

    case O::I32X4TruncSatF32X4S: return DoSimdUnop<s32x4>(IntTruncSat<s32, f32>);
    case O::I32X4TruncSatF32X4U: return DoSimdUnop<u32x4>(IntTruncSat<u32, f32>);
    case O::F32X4ConvertI32X4S:  return DoSimdUnop<f32x4>(Convert<f32, s32>);
    case O::F32X4ConvertI32X4U:  return DoSimdUnop<f32x4>(Convert<f32, u32>);

    case O::V8X16Swizzle:     return DoSimdSwizzle();
    case O::V8X16Shuffle:     return DoSimdShuffle(instr);

    case O::V8X16LoadSplat:   return DoSimdLoadSplat<u8x16, u32>(instr, out_trap);
    case O::V16X8LoadSplat:   return DoSimdLoadSplat<u16x8, u32>(instr, out_trap);
    case O::V32X4LoadSplat:   return DoSimdLoadSplat<u32x4, u32>(instr, out_trap);
    case O::V64X2LoadSplat:   return DoSimdLoadSplat<u64x2, u64>(instr, out_trap);

    case O::I8X16NarrowI16X8S:    return DoSimdNarrow<s8x16, s16x8>();
    case O::I8X16NarrowI16X8U:    return DoSimdNarrow<u8x16, u16x8>();
    case O::I16X8NarrowI32X4S:    return DoSimdNarrow<s16x8, s32x4>();
    case O::I16X8NarrowI32X4U:    return DoSimdNarrow<u16x8, u32x4>();
    case O::I16X8WidenLowI8X16S:  return DoSimdWiden<s16x8, s8x16, true>();
    case O::I16X8WidenHighI8X16S: return DoSimdWiden<s16x8, s8x16, false>();
    case O::I16X8WidenLowI8X16U:  return DoSimdWiden<u16x8, u8x16, true>();
    case O::I16X8WidenHighI8X16U: return DoSimdWiden<u16x8, u8x16, false>();
    case O::I32X4WidenLowI16X8S:  return DoSimdWiden<s32x4, s16x8, true>();
    case O::I32X4WidenHighI16X8S: return DoSimdWiden<s32x4, s16x8, false>();
    case O::I32X4WidenLowI16X8U:  return DoSimdWiden<u32x4, u16x8, true>();
    case O::I32X4WidenHighI16X8U: return DoSimdWiden<u32x4, u16x8, false>();

    case O::I16X8Load8X8S:  return DoSimdLoadExtend<s16x8, s8x8>(instr, out_trap);
    case O::I16X8Load8X8U:  return DoSimdLoadExtend<u16x8, u8x8>(instr, out_trap);
    case O::I32X4Load16X4S: return DoSimdLoadExtend<s32x4, s16x4>(instr, out_trap);
    case O::I32X4Load16X4U: return DoSimdLoadExtend<u32x4, u16x4>(instr, out_trap);
    case O::I64X2Load32X2S: return DoSimdLoadExtend<s64x2, s32x2>(instr, out_trap);
    case O::I64X2Load32X2U: return DoSimdLoadExtend<s64x2, s32x2>(instr, out_trap);

    case O::V128Andnot: return DoSimdBinop<u64x2>(IntAndNot<u64>);
    case O::I8X16AvgrU: return DoSimdBinop<u8x16>(IntAvgr<u8>);
    case O::I16X8AvgrU: return DoSimdBinop<u16x8>(IntAvgr<u16>);

    // The following opcodes are either never generated or should never be
    // executed.
    case O::Nop:
    case O::Block:
    case O::Loop:
    case O::If:
    case O::Else:
    case O::End:
    case O::ReturnCall:
    case O::SelectT:

    case O::Try:
    case O::Catch:
    case O::Throw:
    case O::Rethrow:
    case O::BrOnExn:
    case O::InterpData:
    case O::Invalid:
      WABT_UNREACHABLE;
      break;
  }

  return RunResult::Ok;
}

RunResult Thread::DoCall(const Func::Ptr& func, Trap::Ptr* out_trap) {
  if (auto* host_func = dyn_cast<HostFunc>(func.get())) {
    auto& func_type = host_func->func_type();

    Values params;
    PopValues(func_type.params, &params);
    PushCall(*host_func);

    Values results(func_type.results.size());
    if (Failed(host_func->Call(*this, params, results, out_trap))) {
      return RunResult::Trap;
    }

    PopCall();
    PushValues(func_type.results, results);
  } else {
    PushCall(*cast<DefinedFunc>(func.get()));
  }
  return RunResult::Ok;
}

template <typename T, typename V>
RunResult Thread::Load(Instr instr, V* out, Trap::Ptr* out_trap) {
  Memory::Ptr memory{store_, inst_->memories()[instr.imm_u32x2.fst]};
  u32 offset = Pop<u32>();
  TRAP_IF(Failed(memory->Load(offset, instr.imm_u32x2.snd, out)),
          StringPrintf("access at %u+%u >= max value %u", offset,
                       instr.imm_u32x2.snd, memory->ByteSize()));
  return RunResult::Ok;
}

template <typename T, typename V>
RunResult Thread::DoLoad(Instr instr, Trap::Ptr* out_trap) {
  V val;
  if (Load<V>(instr, &val, out_trap) != RunResult::Ok) {
    return RunResult::Trap;
  }
  Push(static_cast<T>(val));
  return RunResult::Ok;
}

template <typename T, typename V>
RunResult Thread::DoStore(Instr instr, Trap::Ptr* out_trap) {
  Memory::Ptr memory{store_, inst_->memories()[instr.imm_u32x2.fst]};
  u32 offset = Pop<u32>();
  T val = static_cast<T>(Pop<V>());
  TRAP_IF(Failed(memory->Store(offset, instr.imm_u32x2.snd, val)),
          StringPrintf("access at %u+%u >= max value %u", offset,
                       instr.imm_u32x2.snd, memory->ByteSize()));
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoUnop(UnopFunc<R, T> f) {
  Push<T>(f(Pop<T>()));
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoUnop(UnopTrapFunc<R, T> f, Trap::Ptr* out_trap) {
  T out;
  std::string msg;
  TRAP_IF(f(Pop<T>(), &out, &msg) == RunResult::Trap, msg);
  Push<T>(out);
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoBinop(BinopFunc<R, T> f) {
  auto rhs = Pop<T>();
  auto lhs = Pop<T>();
  Push<T>(f(lhs, rhs));
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoBinop(BinopTrapFunc<R, T> f, Trap::Ptr* out_trap) {
  auto rhs = Pop<T>();
  auto lhs = Pop<T>();
  T out;
  std::string msg;
  TRAP_IF(f(lhs, rhs, &out, &msg) == RunResult::Trap, msg);
  Push<T>(out);
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoConvert(Trap::Ptr* out_trap) {
  auto val = Pop<T>();
  TRAP_UNLESS(CanConvert<R>(val), "integer overflow");
  Push<R>(static_cast<R>(val));
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoReinterpret() {
  Push(Bitcast<R>(Pop<T>()));
  return RunResult::Ok;
}

RunResult Thread::DoMemoryInit(Instr instr, Trap::Ptr* out_trap) {
  Memory::Ptr memory{store_, inst_->memories()[instr.imm_u32x2.fst]};
  auto&& data = inst_->datas()[instr.imm_u32x2.snd];
  auto size = Pop<u32>();
  auto src = Pop<u32>();
  auto dst = Pop<u32>();
  TRAP_IF(Failed(memory->Init(dst, data, src, size)),
          "memory.init out of bounds");
  return RunResult::Ok;
}

RunResult Thread::DoDataDrop(Instr instr) {
  inst_->datas()[instr.imm_u32].Drop();
  return RunResult::Ok;
}

RunResult Thread::DoMemoryCopy(Instr instr, Trap::Ptr* out_trap) {
  Memory::Ptr mem_dst{store_, inst_->memories()[instr.imm_u32x2.fst]};
  Memory::Ptr mem_src{store_, inst_->memories()[instr.imm_u32x2.snd]};
  auto size = Pop<u32>();
  auto src = Pop<u32>();
  auto dst = Pop<u32>();
  TRAP_IF(Failed(Memory::Copy(*mem_dst, dst, *mem_src, src, size)),
          "memory.copy out of bounds");
  return RunResult::Ok;
}

RunResult Thread::DoMemoryFill(Instr instr, Trap::Ptr* out_trap) {
  Memory::Ptr memory{store_, inst_->memories()[instr.imm_u32]};
  auto size = Pop<u32>();
  auto value = Pop<u32>();
  auto dst = Pop<u32>();
  TRAP_IF(Failed(memory->Fill(dst, value, size)), "memory.fill out of bounds");
  return RunResult::Ok;
}

RunResult Thread::DoTableInit(Instr instr, Trap::Ptr* out_trap) {
  Table::Ptr table{store_, inst_->tables()[instr.imm_u32x2.fst]};
  auto&& elem = inst_->elems()[instr.imm_u32x2.snd];
  auto size = Pop<u32>();
  auto src = Pop<u32>();
  auto dst = Pop<u32>();
  TRAP_IF(Failed(table->Init(store_, dst, elem, src, size)),
          "table.init out of bounds");
  return RunResult::Ok;
}

RunResult Thread::DoElemDrop(Instr instr) {
  inst_->elems()[instr.imm_u32].Drop();
  return RunResult::Ok;
}

RunResult Thread::DoTableCopy(Instr instr, Trap::Ptr* out_trap) {
  Table::Ptr table_dst{store_, inst_->tables()[instr.imm_u32x2.fst]};
  Table::Ptr table_src{store_, inst_->tables()[instr.imm_u32x2.snd]};
  auto size = Pop<u32>();
  auto src = Pop<u32>();
  auto dst = Pop<u32>();
  TRAP_IF(Failed(Table::Copy(store_, *table_dst, dst, *table_src, src, size)),
          "table.copy out of bounds");
  return RunResult::Ok;
}

RunResult Thread::DoTableGet(Instr instr, Trap::Ptr* out_trap) {
  Table::Ptr table{store_, inst_->tables()[instr.imm_u32]};
  auto index = Pop<u32>();
  Ref ref;
  TRAP_IF(
      Failed(table->Get(index, &ref)),
      StringPrintf("table.get at %u >= max value %u", index, table->size()));
  Push(ref);
  return RunResult::Ok;
}

RunResult Thread::DoTableSet(Instr instr, Trap::Ptr* out_trap) {
  Table::Ptr table{store_, inst_->tables()[instr.imm_u32]};
  auto ref = Pop<Ref>();
  auto index = Pop<u32>();
  TRAP_IF(
      Failed(table->Set(store_, index, ref)),
      StringPrintf("table.set at %u >= max value %u", index, table->size()));
  return RunResult::Ok;
}

RunResult Thread::DoTableGrow(Instr instr, Trap::Ptr* out_trap) {
  Table::Ptr table{store_, inst_->tables()[instr.imm_u32]};
  u32 old_size = table->size();
  auto delta = Pop<u32>();
  auto ref = Pop<Ref>();
  if (Failed(table->Grow(store_, delta, ref))) {
    Push<s32>(-1);
  } else {
    Push<u32>(old_size);
  }
  return RunResult::Ok;
}

RunResult Thread::DoTableSize(Instr instr) {
  Table::Ptr table{store_, inst_->tables()[instr.imm_u32]};
  Push<u32>(table->size());
  return RunResult::Ok;
}

RunResult Thread::DoTableFill(Instr instr, Trap::Ptr* out_trap) {
  Table::Ptr table{store_, inst_->tables()[instr.imm_u32]};
  auto size = Pop<u32>();
  auto value = Pop<Ref>();
  auto dst = Pop<u32>();
  TRAP_IF(Failed(table->Fill(store_, dst, value, size)),
          "table.fill out of bounds");
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoSimdSplat() {
  auto val = Pop<T>();
  R result;
  std::fill(std::begin(result.v), std::end(result.v), val);
  Push(result);
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoSimdExtract(Instr instr) {
  Push<T>(Pop<R>().v[instr.imm_u8]);
  return RunResult::Ok;
}

template <typename R, typename T>
RunResult Thread::DoSimdReplace(Instr instr) {
  auto val = Pop<T>();
  auto simd = Pop<R>();
  simd.v[instr.imm_u8] = val;
  Push(simd);
  return RunResult::Ok;
}

template <typename S, typename R, typename T>
RunResult Thread::DoSimdUnop(UnopFunc<R, T> f) {
  auto val = Pop<S>();
  S result;
  std::transform(std::begin(val.v), std::end(val.v), std::begin(result.v), f);
  Push(val);
  return RunResult::Ok;
}

template <typename S, typename R, typename T>
RunResult Thread::DoSimdBinop(BinopFunc<R, T> f) {
  auto rhs = Pop<S>();
  auto lhs = Pop<S>();
  S result;
  for (u8 i = 0; i < S::lanes; ++i) {
    result.v[i] = f(lhs.v[i], rhs.v[i]);
  }
  Push(result);
  return RunResult::Ok;
}

RunResult Thread::DoSimdBitSelect() {
  using S = u64x2;
  auto c = Pop<S>();
  auto rhs = Pop<S>();
  auto lhs = Pop<S>();
  S result;
  for (u8 i = 0; i < S::lanes; ++i) {
    result.v[i] = (lhs.v[i] & c.v[i]) | (rhs.v[i] & ~c.v[i]);
  }
  Push(result);
  return RunResult::Ok;
}

template <typename S, u8 count>
RunResult Thread::DoSimdIsTrue() {
  using L = typename S::LaneType;
  auto val = Pop<S>();
  Push(std::count_if(std::begin(val.v), std::end(val.v),
                     [](L x) { return x != 0; }) >= count);
  return RunResult::Ok;
}

template <typename S, typename R, typename T>
RunResult Thread::DoSimdShift(BinopFunc<R, T> f) {
  auto amount = Pop<T>();
  auto lhs = Pop<S>();
  S result;
  for (u8 i = 0; i < S::lanes; ++i) {
    result.v[i] = f(lhs.v[i], amount);
  }
  Push(result);
  return RunResult::Ok;
}

template <typename S, typename T>
RunResult Thread::DoSimdLoadSplat(Instr instr, Trap::Ptr* out_trap) {
  using L = typename S::LaneType;
  L val;
  if (Load<L>(instr, &val, out_trap) != RunResult::Ok) {
    return RunResult::Trap;
  }
  S result;
  std::fill(std::begin(result.v), std::end(result.v), val);
  Push(result);
  return RunResult::Ok;
}

RunResult Thread::DoSimdSwizzle() {
  using S = u8x16;
  auto rhs = Pop<S>();
  auto lhs = Pop<S>();
  S result;
  for (u8 i = 0; i < S::lanes; ++i) {
    result.v[i] = rhs.v[i] < S::lanes ? lhs.v[rhs.v[i]] : 0;
  }
  Push(result);
  return RunResult::Ok;
}

RunResult Thread::DoSimdShuffle(Instr instr) {
  using S = u8x16;
  auto sel = instr.imm_v128;
  auto rhs = Pop<S>();
  auto lhs = Pop<S>();
  S result;
  for (u8 i = 0; i < S::lanes; ++i) {
    result.v[i] =
        sel.v[i] < S::lanes ? lhs.v[sel.v[i]] : rhs.v[sel.v[i] - S::lanes];
  }
  Push(result);
  return RunResult::Ok;
}

template <typename S, typename T>
RunResult Thread::DoSimdNarrow() {
  using SL = typename S::LaneType;
  using TL = typename T::LaneType;
  auto rhs = Pop<T>();
  auto lhs = Pop<T>();
  S result;
  for (u8 i = 0; i < T::lanes; ++i) {
    result.v[i] = Saturate<SL, TL>(lhs.v[i]);
  }
  for (u8 i = 0; i < T::lanes; ++i) {
    result.v[T::lanes + i] = Saturate<SL, TL>(rhs.v[i]);
  }
  Push(result);
  return RunResult::Ok;
}

template <typename S, typename T, bool low>
RunResult Thread::DoSimdWiden() {
  auto val = Pop<T>();
  S result;
  for (u8 i = 0; i < S::lanes; ++i) {
    result.v[i] = val.v[(low ? 0 : S::lanes) + i];
  }
  Push(result);
  return RunResult::Ok;
}

template <typename S, typename T>
RunResult Thread::DoSimdLoadExtend(Instr instr, Trap::Ptr* out_trap) {
  T val;
  if (Load<T>(instr, &val, out_trap) != RunResult::Ok) {
    return RunResult::Trap;
  }
  S result;
  for (u8 i = 0; i < S::lanes; ++i) {
    result.v[i] = val.v[i];
  }
  Push(result);
  return RunResult::Ok;
}

Thread::TraceSource::TraceSource(Thread* thread) : thread_(thread) {}

std::string Thread::TraceSource::Pick(Index index, Instr instr) {
  Value val = thread_->Pick(index);
  const char* reftype;
  auto type = instr.op.GetParamType(index);
  if (type == ValueType::Void) {
    // Void should never be displayed normally; we only expect to see it when
    // the stack may have different a different type. This is likely to occur
    // with an index; try to see which type we should expect.
    switch (instr.op) {
      case Opcode::GlobalSet: type = GetGlobalType(instr.imm_u32); break;
      case Opcode::LocalSet:
      case Opcode::LocalTee:  type = GetLocalType(instr.imm_u32); break;
      case Opcode::TableSet:
      case Opcode::TableGrow:
      case Opcode::TableFill: type = GetTableElementType(instr.imm_u32); break;
      default: return "?";
    }
  }

  switch (type) {
    case ValueType::I32: return StringPrintf("%u", val.Get<u32>());
    case ValueType::I64: return StringPrintf("%" PRIu64, val.Get<u64>());
    case ValueType::F32: return StringPrintf("%g", val.Get<f32>());
    case ValueType::F64: return StringPrintf("%g", val.Get<f64>());
    case ValueType::V128: {
      auto v = val.Get<v128>();
      return StringPrintf("0x%08x 0x%08x 0x%08x 0x%08x", v.v[0], v.v[1], v.v[2],
                          v.v[3]);
    }

    case ValueType::Nullref: reftype = "nullref"; break;
    case ValueType::Funcref: reftype = "funcref"; break;
    case ValueType::Exnref:  reftype = "exnref"; break;
    case ValueType::Anyref:  reftype = "anyref"; break;

    default:
      WABT_UNREACHABLE;
      break;
  }

  // Handle ref types.
  return StringPrintf("%s:%" PRIzd, reftype, val.Get<Ref>().index);
}

ValueType Thread::TraceSource::GetLocalType(Index stack_slot) {
  const Frame& frame = thread_->frames_.back();
  DefinedFunc::Ptr func{thread_->store_, frame.func};
  Index local_index = (thread_->values_.size() - frame.values) - stack_slot - 1;
  return func->desc().GetLocalType(local_index);
}

ValueType Thread::TraceSource::GetGlobalType(Index index) {
  return thread_->mod_->desc().globals[index].type.type;
}

ValueType Thread::TraceSource::GetTableElementType(Index index) {
  return thread_->mod_->desc().tables[index].type.element;
}

}  // namespace interp2
}  // namespace wabt
