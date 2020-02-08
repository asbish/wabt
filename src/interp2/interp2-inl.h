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

#include <cassert>
#include <string>

namespace wabt {
namespace interp2 {

//// Ref ////
inline Ref::Ref(size_t index) : index(index) {}

inline bool operator==(Ref lhs, Ref rhs) {
  return lhs.index == rhs.index;
}

inline bool operator!=(Ref lhs, Ref rhs) {
  return lhs.index != rhs.index;
}

//// ExternType ////
inline ExternType::ExternType(ExternKind kind) : kind(kind) {}

//// FuncType ////
// static
inline bool FuncType::classof(const ExternType* type) {
  return type->kind == skind;
}

inline FuncType::FuncType(ValueTypes params, ValueTypes results)
    : ExternType(ExternKind::Func), params(params), results(results) {}

//// TableType ////
// static
inline bool TableType::classof(const ExternType* type) {
  return type->kind == skind;
}

inline TableType::TableType(ValueType element, Limits limits)
    : ExternType(ExternKind::Table), element(element), limits(limits) {}

//// MemoryType ////
// static
inline bool MemoryType::classof(const ExternType* type) {
  return type->kind == skind;
}

inline MemoryType::MemoryType(Limits limits)
    : ExternType(ExternKind::Memory), limits(limits) {}

//// GlobalType ////
// static
inline bool GlobalType::classof(const ExternType* type) {
  return type->kind == skind;
}

inline GlobalType::GlobalType(ValueType type, Mutability mut)
    : ExternType(ExternKind::Global), type(type), mut(mut) {}

//// EventType ////
// static
inline bool EventType::classof(const ExternType* type) {
  return type->kind == skind;
}

inline EventType::EventType(EventAttr attr, const ValueTypes& signature)
    : ExternType(ExternKind::Event), attr(attr), signature(signature) {}

//// ImportType ////
inline ImportType::ImportType(std::string module,
                              std::string name,
                              std::unique_ptr<ExternType> type)
    : module(module), name(name), type(std::move(type)) {}

inline ImportType::ImportType(const ImportType& other)
    : module(other.module), name(other.name), type(other.type->Clone()) {}

inline ImportType& ImportType::operator=(const ImportType& other) {
  if (this != &other) {
    module = other.module;
    name = other.name;
    type = other.type->Clone();
  }
  return *this;
}

//// ExportType ////
inline ExportType::ExportType(std::string name,
                              std::unique_ptr<ExternType> type)
    : name(name), type(std::move(type)) {}

inline ExportType::ExportType(const ExportType& other)
    : name(other.name), type(other.type->Clone()) {}

inline ExportType& ExportType::operator=(const ExportType& other) {
  if (this != &other) {
    name = other.name;
    type = other.type->Clone();
  }
  return *this;
}

//// Frame ////
inline Frame::Frame(Ref func,
                    u32 values,
                    u32 offset,
                    Instance* inst,
                    Module* mod)
    : func(func), values(values), offset(offset), inst(inst), mod(mod) {}

//// FreeList ////
template <typename T>
bool FreeList<T>::IsValid(Index index) const {
  return index < list.size();
}

template <typename T>
template <typename... Args>
typename FreeList<T>::Index FreeList<T>::New(Args&&... args) {
  if (!free.empty()) {
    Index index = free.back();
    free.pop_back();
    list[index] = T(std::forward<Args>(args)...);
    return index;
  }
  list.emplace_back(std::forward<Args>(args)...);
  return list.size() - 1;
}

template <typename T>
void FreeList<T>::Delete(Index index) {
  assert(IsValid(index));
  list[index].~T();
  free.push_back(index);
}

template <typename T>
const T& FreeList<T>::Get(Index index) const {
  assert(IsValid(index));
  return list[index];
}

template <typename T>
T& FreeList<T>::Get(Index index) {
  assert(IsValid(index));
  return list[index];
}

//// RefPtr ////
template <typename T>
RefPtr<T>::RefPtr() : obj_(nullptr), store_(nullptr), root_index_(0) {}

template <typename T>
RefPtr<T>::RefPtr(Store& store, Ref ref) {
  assert(store.Is<T>(ref));
  root_index_ = store.NewRoot(ref);
  obj_ = static_cast<T*>(store.objects_.Get(ref.index).get());
  store_ = &store;
}

template <typename T>
RefPtr<T>::RefPtr(const RefPtr& other)
    : obj_(other.obj_), store_(other.store_) {
  root_index_ = store_ ? store_->CopyRoot(other.root_index_) : 0;
}

template <typename T>
RefPtr<T>& RefPtr<T>::operator=(const RefPtr& other) {
  obj_ = other.obj_;
  store_ = other.store_;
  root_index_ = store_ ? store_->CopyRoot(other.root_index_) : 0;
}

template <typename T>
RefPtr<T>::RefPtr(RefPtr&& other)
    : obj_(other.obj_), store_(other.store_), root_index_(other.root_index_) {
  other.obj_ = nullptr;
  other.store_ = nullptr;
  other.root_index_ = 0;
}

template <typename T>
RefPtr<T>& RefPtr<T>::operator=(RefPtr&& other) {
  obj_ = other.obj_;
  store_ = other.store_;
  root_index_ = other.root_index_;
  other.obj_ = nullptr;
  other.store_ = nullptr;
  other.root_index_ = 0;
  return *this;
}

template <typename T>
RefPtr<T>::~RefPtr() {
  reset();
}

template <typename T>
bool RefPtr<T>::empty() const {
  return obj_ != nullptr;
}

template <typename T>
void RefPtr<T>::reset() {
  if (obj_) {
    store_->DeleteRoot(root_index_);
    obj_ = nullptr;
    root_index_ = 0;
    store_ = nullptr;
  }
}

template <typename T>
T* RefPtr<T>::get() const {
  return obj_;
}

template <typename T>
T* RefPtr<T>::operator->() const {
  return obj_;
}

template <typename T>
T& RefPtr<T>::operator*() const {
  return *obj_;
}

template <typename T>
RefPtr<T>::operator bool() const {
  return obj_ != nullptr;
}

template <typename T>
Ref RefPtr<T>::ref() const {
  return store_ ? store_->roots_.Get(root_index_) : Ref::Null;
}

//// ValueType ////
inline bool IsReference(ValueType type) { return IsRefType(type); }
template <> inline bool HasType<s32>(ValueType type) { return type == ValueType::I32; }
template <> inline bool HasType<u32>(ValueType type) { return type == ValueType::I32; }
template <> inline bool HasType<s64>(ValueType type) { return type == ValueType::I64; }
template <> inline bool HasType<u64>(ValueType type) { return type == ValueType::I64; }
template <> inline bool HasType<f32>(ValueType type) { return type == ValueType::F32; }
template <> inline bool HasType<f64>(ValueType type) { return type == ValueType::F64; }
template <> inline bool HasType<Ref>(ValueType type) { return IsReference(type); }

template <typename T> void RequireType(ValueType type) {
  assert(HasType<T>(type));
}

inline bool TypesMatch(ValueType expected, ValueType actual) {
  if (expected == actual) {
    return true;
  }
  if (!IsReference(expected)) {
    return false;
  }
  if (expected == ValueType::Anyref || actual == ValueType::Nullref) {
    return true;
  }
  return false;
}

//// Value ////
inline Value::Value(s32 val) : i32_(val) {}
inline Value::Value(u32 val) : i32_(val) {}
inline Value::Value(s64 val) : i64_(val) {}
inline Value::Value(u64 val) : i64_(val) {}
inline Value::Value(f32 val) : f32_(val) {}
inline Value::Value(f64 val) : f64_(val) {}
inline Value::Value(v128 val): v128_(val) {}
inline Value::Value(Ref val): ref_(val) {}

template <typename T, u8 L>
Value::Value(Simd<T, L> val) : v128_(Bitcast<v128>(val)) {}

template <> inline s8 Value::Get<s8>() const { return i32_; }
template <> inline u8 Value::Get<u8>() const { return i32_; }
template <> inline s16 Value::Get<s16>() const { return i32_; }
template <> inline u16 Value::Get<u16>() const { return i32_; }
template <> inline s32 Value::Get<s32>() const { return i32_; }
template <> inline u32 Value::Get<u32>() const { return i32_; }
template <> inline s64 Value::Get<s64>() const { return i64_; }
template <> inline u64 Value::Get<u64>() const { return i64_; }
template <> inline f32 Value::Get<f32>() const { return f32_; }
template <> inline f64 Value::Get<f64>() const { return f64_; }
template <> inline v128 Value::Get<v128>() const { return v128_; }
template <> inline Ref Value::Get<Ref>() const { return ref_; }

template <> inline s8x16 Value::Get<s8x16>() const { return Bitcast<s8x16>(v128_); }
template <> inline u8x16 Value::Get<u8x16>() const { return Bitcast<u8x16>(v128_); }
template <> inline s16x8 Value::Get<s16x8>() const { return Bitcast<s16x8>(v128_); }
template <> inline u16x8 Value::Get<u16x8>() const { return Bitcast<u16x8>(v128_); }
template <> inline s32x4 Value::Get<s32x4>() const { return Bitcast<s32x4>(v128_); }
template <> inline u32x4 Value::Get<u32x4>() const { return Bitcast<u32x4>(v128_); }
template <> inline s64x2 Value::Get<s64x2>() const { return Bitcast<s64x2>(v128_); }
template <> inline u64x2 Value::Get<u64x2>() const { return Bitcast<u64x2>(v128_); }
template <> inline f32x4 Value::Get<f32x4>() const { return Bitcast<f32x4>(v128_); }
template <> inline f64x2 Value::Get<f64x2>() const { return Bitcast<f64x2>(v128_); }

template <> inline void Value::Set<s32>(s32 val) { i32_ = val; }
template <> inline void Value::Set<u32>(u32 val) { i32_ = val; }
template <> inline void Value::Set<s64>(s64 val) { i64_ = val; }
template <> inline void Value::Set<u64>(u64 val) { i64_ = val; }
template <> inline void Value::Set<f32>(f32 val) { f32_ = val; }
template <> inline void Value::Set<f64>(f64 val) { f64_ = val; }
template <> inline void Value::Set<v128>(v128 val) { v128_ = val; }
template <> inline void Value::Set<Ref>(Ref val) { ref_ = val; }

//// Store ////
inline bool Store::IsValid(Ref ref) const {
  return objects_.IsValid(ref.index) && objects_.Get(ref.index);
}

template <typename T>
bool Store::Is(Ref ref) const {
  return objects_.IsValid(ref.index) && isa<T>(objects_.Get(ref.index).get());
}

template <typename T>
Result Store::Get(Ref ref, RefPtr<T>* out) {
  if (Is<T>(ref)) {
    *out = RefPtr<T>(*this, ref);
    return Result::Ok;
  }
  return Result::Error;
}

template <typename T>
RefPtr<T> Store::UnsafeGet(Ref ref) {
  return RefPtr<T>(*this, ref);
}

template <typename T, typename... Args>
RefPtr<T> Store::Alloc(Args&&... args) {
  Ref ref{objects_.New(new T(std::forward<Args>(args)...))};
  RefPtr<T> ptr{*this, ref};
  ptr->self_ = ref;
  return ptr;
}

//// Object ////
// static
inline bool Object::classof(const Object* obj) {
  return true;
}

inline Object::Object(ObjectKind kind) : kind_(kind) {}

inline ObjectKind Object::kind() const {
  return kind_;
}

inline Ref Object::self() const {
  return self_;
}

inline Finalizer Object::get_finalizer() const {
  return finalizer_;
}

inline void Object::set_finalizer(Finalizer finalizer) {
  finalizer_ = finalizer;
}

//// Foreign ////
// static
inline bool Foreign::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Foreign::Ptr Foreign::New(Store& store, void* ptr) {
  return store.Alloc<Foreign>(store, ptr);
}

inline void* Foreign::ptr() {
  return ptr_;
}

//// Trap ////
// static
inline bool Trap::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Trap::Ptr Trap::New(Store& store,
                           const std::string& msg,
                           const std::vector<Frame>& trace) {
  return store.Alloc<Trap>(store, msg, trace);
}

inline std::string Trap::message() const {
  return message_;
}

//// Extern ////
// static
inline bool Extern::classof(const Object* obj) {
  switch (obj->kind()) {
    case ObjectKind::DefinedFunc:
    case ObjectKind::HostFunc:
    case ObjectKind::Table:
    case ObjectKind::Memory:
    case ObjectKind::Global:
    case ObjectKind::Event:
      return true;
    default:
      return false;
  }
}

inline Extern::Extern(ObjectKind kind) : Object(kind) {}

//// Func ////
// static
inline bool Func::classof(const Object* obj) {
  switch (obj->kind()) {
    case ObjectKind::DefinedFunc:
    case ObjectKind::HostFunc:
      return true;
    default:
      return false;
  }
}

inline const FuncType& Func::func_type() const {
  return type_;
}

//// DefinedFunc ////
// static
inline bool DefinedFunc::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline DefinedFunc::Ptr DefinedFunc::New(Store& store,
                                         Ref instance,
                                         FuncDesc desc) {
  return store.Alloc<DefinedFunc>(store, instance, desc);
}

inline Ref DefinedFunc::instance() const {
  return instance_;
}

inline const FuncDesc& DefinedFunc::desc() const {
  return desc_;
}

//// HostFunc ////
// static
inline bool HostFunc::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline HostFunc::Ptr HostFunc::New(Store& store, FuncType type, Callback cb) {
  return store.Alloc<HostFunc>(store, type, cb);
}

//// Table ////
// static
inline bool Table::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Table::Ptr Table::New(Store& store, TableDesc desc) {
  return store.Alloc<Table>(store, desc);
}

inline const TableDesc& Table::desc() const {
  return desc_;
}

inline const RefVec& Table::elements() const {
  return elements_;
}

inline u32 Table::size() const {
  return static_cast<u32>(elements_.size());
}

//// Memory ////
// static
inline bool Memory::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Memory::Ptr Memory::New(interp2::Store& store, MemoryDesc desc) {
  return store.Alloc<Memory>(store, desc);
}

inline bool Memory::IsValidAccess(u32 offset, u32 addend, size_t size) const {
  size_t data_size = data_.size();
  return size <= data_size && addend <= data_size - size &&
         offset <= data_size - size - addend;
}

template <typename T>
Result Memory::Load(u32 offset, u32 addend, T* out) const {
  if (IsValidAccess(offset, addend, sizeof(T))) {
    memcpy(out, data_.data() + offset + addend, sizeof(T));
    return Result::Ok;
  }
  return Result::Error;
}

template <typename T>
T Memory::UnsafeLoad(u32 offset, u32 addend) const {
  assert(IsValidAccess(offset, addend, sizeof(T)));
  T val;
  memcpy(&val, data_.data() + offset + addend, sizeof(T));
  return val;
}

template <typename T>
Result Memory::Store(u32 offset, u32 addend, T val) {
  if (IsValidAccess(offset, addend, sizeof(T))) {
    memcpy(data_.data() + offset + addend, &val, sizeof(T));
    return Result::Ok;
  }
  return Result::Error;
}

inline u32 Memory::ByteSize() const {
  return data_.size();
}

inline u32 Memory::PageSize() const {
  return pages_;
}

//// Global ////
// static
inline bool Global::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Global::Ptr Global::New(Store& store, GlobalDesc desc, Value value) {
  return store.Alloc<Global>(store, desc, value);
}

inline Value Global::Get() const {
  return value_;
}

template <typename T>
Result Global::Get(T* out) const {
  if (HasType<T>(desc_.type.type)) {
    *out = value_.Get<T>();
    return Result::Ok;
  }
  return Result::Error;
}

template <typename T>
T Global::UnsafeGet() const {
  RequireType<T>(desc_.type.type);
  return value_.Get<T>();
}

template <typename T>
Result Global::Set(T val) {
  if (desc_.type.mut == Mutability::Var && HasType<T>(desc_.type.type)) {
    value_.Set(val);
    return Result::Ok;
  }
  return Result::Error;
}

//// Event ////
// static
inline bool Event::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Event::Ptr Event::New(Store& store, EventDesc desc) {
  return store.Alloc<Event>(store, desc);
}

//// ElemSegment ////
inline void ElemSegment::Drop() {
  elements_.clear();
}

inline const ElemDesc& ElemSegment::desc() const {
  return *desc_;
}

inline const RefVec& ElemSegment::elements() const {
  return elements_;
}

inline u32 ElemSegment::size() const {
  return elements_.size();
}

//// DataSegment ////
inline void DataSegment::Drop() {
  size_ = 0;
}

inline const DataDesc& DataSegment::desc() const {
  return *desc_;
}

inline u32 DataSegment::size() const {
  return size_;
}

//// Module ////
// static
inline bool Module::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Module::Ptr Module::New(Store& store, ModuleDesc desc) {
  return store.Alloc<Module>(store, std::move(desc));
}

inline const ModuleDesc& Module::desc() const {
  return desc_;
}

inline const std::vector<ImportType>& Module::import_types() const {
  return import_types_;
}

inline const std::vector<ExportType>& Module::export_types() const {
  return export_types_;
}

//// Instance ////
// static
inline bool Instance::classof(const Object* obj) {
  return obj->kind() == skind;
}

inline Ref Instance::module() const {
  return module_;
}

inline const RefVec& Instance::imports() const {
  return imports_;
}

inline const RefVec& Instance::funcs() const {
  return funcs_;
}

inline const RefVec& Instance::tables() const {
  return tables_;
}

inline const RefVec& Instance::memories() const {
  return memories_;
}

inline const RefVec& Instance::globals() const {
  return globals_;
}

inline const RefVec& Instance::events() const {
  return events_;
}

inline const RefVec& Instance::exports() const {
  return exports_;
}

inline const std::vector<ElemSegment>& Instance::elems() const {
  return elems_;
}

inline std::vector<ElemSegment>& Instance::elems() {
  return elems_;
}

inline const std::vector<DataSegment>& Instance::datas() const {
  return datas_;
}

inline std::vector<DataSegment>& Instance::datas() {
  return datas_;
}

//// Thread ////
// static
inline bool Thread::classof(const Object* obj) {
  return obj->kind() == skind;
}

// static
inline Thread::Ptr Thread::New(Store& store, const Options& options) {
  return store.Alloc<Thread>(store, options);
}

inline Store& Thread::store() {
  return store_;
}

}  // namespace interp2
}  // namespace wabt
