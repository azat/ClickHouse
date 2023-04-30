#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <variant>
#include <optional>
#include <sparsehash/sparse_hash_map>
#include <sparsehash/sparse_hash_set>

#include <Common/HashTable/HashMap.h>
#include <Common/HashTable/HashSet.h>
#include <Core/Block.h>

#include <Dictionaries/DictionaryStructure.h>
#include <Dictionaries/IDictionary.h>
#include <Dictionaries/IDictionarySource.h>
#include <Dictionaries/DictionaryHelpers.h>

/** This dictionary stores all content in a hash table in memory
  * (a separate Key -> Value map for each attribute)
  * Two variants of hash table are supported: a fast HashMap and memory efficient sparse_hash_map.
  */

namespace DB
{

/// A pair that does not initialize the elements, if not needed.
template <typename First, typename Second>
struct PackedPairNoInit
{
    First first;
    Second second;

    PackedPairNoInit() {} /// NOLINT

    template <typename FirstValue>
    PackedPairNoInit(FirstValue && first_, NoInitTag)
        : first(std::forward<FirstValue>(first_))
    {
    }

    template <typename FirstValue, typename SecondValue>
    PackedPairNoInit(FirstValue && first_, SecondValue && second_)
        : first(std::forward<FirstValue>(first_))
        , second(std::forward<SecondValue>(second_))
    {
    }
} __attribute__((packed));
template <typename First, typename Second>
PackedPairNoInit<std::decay_t<First>, std::decay_t<Second>> makePairNoInit(First && first, Second && second)
{
    return PackedPairNoInit<std::decay_t<First>, std::decay_t<Second>>(std::forward<First>(first), std::forward<Second>(second));
}

template <typename Key, typename TMapped, typename Hash, typename TState = HashTableNoState>
struct PackedHashMapCell
{
    using Mapped = TMapped;
    using State = TState;

    using value_type = PackedPairNoInit<Key, Mapped>;
    using mapped_type = Mapped;
    using key_type = Key;

    value_type value;

    PackedHashMapCell() = default;
    PackedHashMapCell(const Key & key_, const State &) : value(key_, NoInitTag()) {}
    PackedHashMapCell(const value_type & value_, const State &) : value(value_) {}

    /// Get the key (externally).
    const Key & getKey() const { return value.first; }
    Mapped & getMapped() { return value.second; }
    const Mapped & getMapped() const { return value.second; }
    const value_type & getValue() const { return value; }

    /// Get the key (internally).
    static const Key & getKey(const value_type & value) { return value.first; }

    bool keyEquals(const Key & key_) const { return bitEquals(value.first, key_); }
    bool keyEquals(const Key & key_, size_t /*hash_*/) const { return bitEquals(value.first, key_); }
    bool keyEquals(const Key & key_, size_t /*hash_*/, const State & /*state*/) const { return bitEquals(value.first, key_); }

    void setHash(size_t /*hash_value*/) {}
    size_t getHash(const Hash & hash) const { return hash(value.first); }

    bool isZero(const State & state) const { return isZero(value.first, state); }
    static bool isZero(const Key & key, const State & /*state*/) { return ZeroTraits::check(key); }

    /// Set the key value to zero.
    void setZero() { ZeroTraits::set(value.first); }

    /// Do I need to store the zero key separately (that is, can a zero key be inserted into the hash table).
    static constexpr bool need_zero_value_storage = true;

    void setMapped(const value_type & value_) { value.second = value_.second; }

    /// Serialization, in binary and text form.
    void write(DB::WriteBuffer & wb) const
    {
        DB::writeBinary(value.first, wb);
        DB::writeBinary(value.second, wb);
    }

    void writeText(DB::WriteBuffer & wb) const
    {
        DB::writeDoubleQuoted(value.first, wb);
        DB::writeChar(',', wb);
        DB::writeDoubleQuoted(value.second, wb);
    }

    /// Deserialization, in binary and text form.
    void read(DB::ReadBuffer & rb)
    {
        DB::readBinary(value.first, rb);
        DB::readBinary(value.second, rb);
    }

    void readText(DB::ReadBuffer & rb)
    {
        DB::readDoubleQuoted(value.first, rb);
        DB::assertChar(',', rb);
        DB::readDoubleQuoted(value.second, rb);
    }

    static bool constexpr need_to_notify_cell_during_move = false;

    static void move(PackedHashMapCell * /* old_location */, PackedHashMapCell * /* new_location */) {}

    template <size_t I>
    auto & get() & {
        if constexpr (I == 0) return value.first;
        else if constexpr (I == 1) return value.second;
    }

    template <size_t I>
    auto const & get() const & {
        if constexpr (I == 0) return value.first;
        else if constexpr (I == 1) return value.second;
    }

    template <size_t I>
    auto && get() && {
        if constexpr (I == 0) return std::move(value.first);
        else if constexpr (I == 1) return std::move(value.second);
    }

};

}

namespace std
{
    template <typename Key, typename TMapped, typename Hash, typename TState>
    struct tuple_size<DB::PackedHashMapCell<Key, TMapped, Hash, TState>> : std::integral_constant<size_t, 2> { };

    template <typename Key, typename TMapped, typename Hash, typename TState>
    struct tuple_element<0, DB::PackedHashMapCell<Key, TMapped, Hash, TState>> { using type = Key; };

    template <typename Key, typename TMapped, typename Hash, typename TState>
    struct tuple_element<1, DB::PackedHashMapCell<Key, TMapped, Hash, TState>> { using type = TMapped; };
}

namespace DB
{

template <size_t initial_size_degree = 8>
class alignas(64) HashedHashTableGrower
{
    /// The state of this structure is enough to get the buffer size of the hash table.

    UInt8 size_degree = initial_size_degree;
    size_t precalculated_mask = (1ULL << initial_size_degree) - 1;
    size_t precalculated_max_fill = 1ULL << (initial_size_degree - 1);

public:
    UInt8 sizeDegree() const { return size_degree; }

    void increaseSizeDegree(UInt8 delta)
    {
        size_degree += delta;
        precalculated_mask = (1ULL << size_degree) - 1;
        precalculated_max_fill = static_cast<size_t>((1ULL << size_degree) * 0.94);

        fmt::print(stderr, "grower: {}, size_degree: {}, max_fill: {}\n", reinterpret_cast<void*>(this), static_cast<size_t>(size_degree), precalculated_max_fill);
    }

    static constexpr auto initial_count = 1ULL << initial_size_degree;

    /// If collision resolution chains are contiguous, we can implement erase operation by moving the elements.
    static constexpr auto performs_linear_probing_with_single_step = true;

    /// The size of the hash table in the cells.
    size_t bufSize() const { return 1ULL << size_degree; }

    /// From the hash value, get the cell number in the hash table.
    size_t place(size_t x) const { return x & precalculated_mask; }

    /// The next cell in the collision resolution chain.
    size_t next(size_t pos) const { return (pos + 1) & precalculated_mask; }

    /// Whether the hash table is sufficiently full. You need to increase the size of the hash table, or remove something unnecessary from it.
    bool overflow(size_t elems) const { return elems > precalculated_max_fill; }

    /// Increase the size of the hash table.
    void increaseSize() { increaseSizeDegree(size_degree >= 23 ? 1 : 2); }

    /// Set the buffer size by the number of elements in the hash table. Used when deserializing a hash table.
    void set(size_t num_elems)
    {
        size_degree = num_elems <= 1
             ? initial_size_degree
             : ((initial_size_degree > static_cast<size_t>(log2(num_elems - 1)) + 2)
                 ? initial_size_degree
                 : (static_cast<size_t>(log2(num_elems - 1)) + 2));
        increaseSizeDegree(0);
    }

    void setBufSize(size_t buf_size_)
    {
        size_degree = static_cast<size_t>(log2(buf_size_ - 1) + 1);
        increaseSizeDegree(0);
    }
};

template <
    typename Key,
    typename Mapped,
    typename Hash = DefaultHash<Key>,
    typename Grower = HashedHashTableGrower<>,
    typename Allocator = HashTableAllocator>
using PackedHashMap = HashMapTable<Key, PackedHashMapCell<Key, Mapped, Hash>, Hash, Grower, Allocator>;

struct HashedDictionaryConfiguration
{
    const UInt64 shards;
    const UInt64 shard_load_queue_backlog;
    const bool require_nonempty;
    const DictionaryLifetime lifetime;
};

static Int64 hashed_dictionary_allocated = 0;
/// NOTE: custom allocator does not have realloc, hence sparsehash cannot use memmove (memcpy())
template <class T>
class HashedDictionaryAllocator
{
public:
    using value_type = T;
    using size_type = uint64_t;
    using difference_type = ptrdiff_t;

    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    HashedDictionaryAllocator() {}
    HashedDictionaryAllocator(const HashedDictionaryAllocator<T> &) {}
    ~HashedDictionaryAllocator() {}

    template <class U>
    explicit HashedDictionaryAllocator(const HashedDictionaryAllocator<U> &) {}

    [[nodiscard]] T * allocate(size_t n)
    {
        size_t size = sizeof(T) * n;
        hashed_dictionary_allocated += size;
        return reinterpret_cast<T *>(allocator.alloc(size));
    }
    void deallocate(T * ptr, size_t n) noexcept
    {
        size_t size = sizeof(T) * n;
        hashed_dictionary_allocated -= size;
        allocator.free(ptr, size);
    }

    void construct(T * p, const T& val) { new (p) T(val); }
    void destroy(T * p) { p->~T(); }

    size_type max_size() const { return static_cast<size_type>(-1) / sizeof(value_type); }

private:
    Allocator<false, false> allocator;

    void operator=(const HashedDictionaryAllocator<T> &);
};
template <class T>
inline bool operator==(const HashedDictionaryAllocator<T>&,
                       const HashedDictionaryAllocator<T>&) {
    return true;
}
template <class T>
inline bool operator!=(const HashedDictionaryAllocator<T>&,
                       const HashedDictionaryAllocator<T>&) {
    return false;
}


template <DictionaryKeyType dictionary_key_type, bool sparse, bool sharded>
class ParallelDictionaryLoader;

template <DictionaryKeyType dictionary_key_type, bool sparse, bool sharded>
class HashedDictionary final : public IDictionary
{
    friend class ParallelDictionaryLoader<dictionary_key_type, sparse, sharded>;

public:
    using KeyType = std::conditional_t<dictionary_key_type == DictionaryKeyType::Simple, UInt64, StringRef>;

    HashedDictionary(
        const StorageID & dict_id_,
        const DictionaryStructure & dict_struct_,
        DictionarySourcePtr source_ptr_,
        const HashedDictionaryConfiguration & configuration_,
        BlockPtr update_field_loaded_block_ = nullptr);
    ~HashedDictionary() override;

    std::string getTypeName() const override
    {
        if constexpr (dictionary_key_type == DictionaryKeyType::Simple && sparse)
            return "SparseHashed";
        else if constexpr (dictionary_key_type == DictionaryKeyType::Simple && !sparse)
            return "Hashed";
        else if constexpr (dictionary_key_type == DictionaryKeyType::Complex && sparse)
            return "ComplexKeySparseHashed";
        else
            return "ComplexKeyHashed";
    }

    size_t getBytesAllocated() const override { return bytes_allocated; }

    size_t getQueryCount() const override { return query_count.load(std::memory_order_relaxed); }

    double getFoundRate() const override
    {
        size_t queries = query_count.load(std::memory_order_relaxed);
        if (!queries)
            return 0;
        return static_cast<double>(found_count.load(std::memory_order_relaxed)) / queries;
    }

    double getHitRate() const override { return 1.0; }

    size_t getElementCount() const override { return element_count; }

    double getLoadFactor() const override { return static_cast<double>(element_count) / bucket_count; }

    std::shared_ptr<const IExternalLoadable> clone() const override
    {
        return std::make_shared<HashedDictionary<dictionary_key_type, sparse, sharded>>(
            getDictionaryID(),
            dict_struct,
            source_ptr->clone(),
            configuration,
            update_field_loaded_block);
    }

    DictionarySourcePtr getSource() const override { return source_ptr; }

    const DictionaryLifetime & getLifetime() const override { return configuration.lifetime; }

    const DictionaryStructure & getStructure() const override { return dict_struct; }

    bool isInjective(const std::string & attribute_name) const override
    {
        return dict_struct.getAttribute(attribute_name).injective;
    }

    DictionaryKeyType getKeyType() const override { return dictionary_key_type; }

    ColumnPtr getColumn(
        const std::string& attribute_name,
        const DataTypePtr & result_type,
        const Columns & key_columns,
        const DataTypes & key_types,
        const ColumnPtr & default_values_column) const override;

    ColumnUInt8::Ptr hasKeys(const Columns & key_columns, const DataTypes & key_types) const override;

    bool hasHierarchy() const override { return dictionary_key_type == DictionaryKeyType::Simple && dict_struct.hierarchical_attribute_index.has_value(); }

    ColumnPtr getHierarchy(ColumnPtr key_column, const DataTypePtr & hierarchy_attribute_type) const override;

    ColumnUInt8::Ptr isInHierarchy(
        ColumnPtr key_column,
        ColumnPtr in_key_column,
        const DataTypePtr & key_type) const override;

    DictionaryHierarchicalParentToChildIndexPtr getHierarchicalIndex() const override;

    size_t getHierarchicalIndexBytesAllocated() const override { return hierarchical_index_bytes_allocated; }

    ColumnPtr getDescendants(
        ColumnPtr key_column,
        const DataTypePtr & key_type,
        size_t level,
        DictionaryHierarchicalParentToChildIndexPtr parent_to_child_index) const override;

    Pipe read(const Names & column_names, size_t max_block_size, size_t num_streams) const override;

private:
    template <typename Value>
    using CollectionTypeNonSparse = std::conditional_t<
        dictionary_key_type == DictionaryKeyType::Simple,
        PackedHashMap<UInt64, Value, DefaultHash<UInt64>, HashedHashTableGrower<>>,
        HashMapWithSavedHash<StringRef, Value, DefaultHash<StringRef>>>;

    using NoAttributesCollectionTypeNonSparse = std::conditional_t<
        dictionary_key_type == DictionaryKeyType::Simple,
        HashSet<UInt64, DefaultHash<UInt64>>,
        HashSetWithSavedHash<StringRef, DefaultHash<StringRef>>>;

    /// Here we use sparse_hash_map with DefaultHash<> for the following reasons:
    ///
    /// - DefaultHash<> is used for HashMap
    /// - DefaultHash<> (from HashTable/Hash.h> works better then std::hash<>
    ///   in case of sequential set of keys, but with random access to this set, i.e.
    ///
    ///       SELECT number FROM numbers(3000000) ORDER BY rand()
    ///
    ///   And even though std::hash<> works better in some other cases,
    ///   DefaultHash<> is preferred since the difference for this particular
    ///   case is significant, i.e. it can be 10x+.
    template <typename Value>
    using CollectionTypeSparse = std::conditional_t<
        dictionary_key_type == DictionaryKeyType::Simple,
        google::sparse_hash_map<UInt64, Value, DefaultHash<KeyType>, std::equal_to<UInt64>, HashedDictionaryAllocator<google::packed_pair<const UInt64, Value>>>,
        google::sparse_hash_map<StringRef, Value, DefaultHash<KeyType>, std::equal_to<StringRef>, HashedDictionaryAllocator<google::packed_pair<const StringRef, Value>>>>;

    using NoAttributesCollectionTypeSparse = google::sparse_hash_set<KeyType, DefaultHash<KeyType>, std::equal_to<KeyType>, HashedDictionaryAllocator<KeyType>>;

    template <typename Value>
    using CollectionType = std::conditional_t<sparse, CollectionTypeSparse<Value>, CollectionTypeNonSparse<Value>>;

    template <typename Value>
    using CollectionsHolder = std::vector<CollectionType<Value>>;

    using NoAttributesCollectionType = std::conditional_t<sparse, NoAttributesCollectionTypeSparse, NoAttributesCollectionTypeNonSparse>;

    using NullableSet = HashSet<KeyType, DefaultHash<KeyType>>;
    using NullableSets = std::vector<NullableSet>;

    struct Attribute final
    {
        AttributeUnderlyingType type;
        std::optional<NullableSets> is_nullable_sets;

        std::variant<
            CollectionsHolder<UInt8>,
            CollectionsHolder<UInt16>,
            CollectionsHolder<UInt32>,
            CollectionsHolder<UInt64>,
            CollectionsHolder<UInt128>,
            CollectionsHolder<UInt256>,
            CollectionsHolder<Int8>,
            CollectionsHolder<Int16>,
            CollectionsHolder<Int32>,
            CollectionsHolder<Int64>,
            CollectionsHolder<Int128>,
            CollectionsHolder<Int256>,
            CollectionsHolder<Decimal32>,
            CollectionsHolder<Decimal64>,
            CollectionsHolder<Decimal128>,
            CollectionsHolder<Decimal256>,
            CollectionsHolder<DateTime64>,
            CollectionsHolder<Float32>,
            CollectionsHolder<Float64>,
            CollectionsHolder<UUID>,
            CollectionsHolder<IPv4>,
            CollectionsHolder<IPv6>,
            CollectionsHolder<StringRef>,
            CollectionsHolder<Array>>
            containers;
    };

    void createAttributes();

    void blockToAttributes(const Block & block, DictionaryKeysArenaHolder<dictionary_key_type> & arena_holder, UInt64 shard);

    void updateData();

    void loadData();

    void buildHierarchyParentToChildIndexIfNeeded();

    void calculateBytesAllocated();

    UInt64 getShard(UInt64 key) const
    {
        if constexpr (!sharded)
            return 0;
        /// NOTE: function here should not match with the DefaultHash<> since
        /// it used for the HashMap/sparse_hash_map.
        return intHashCRC32(key) % configuration.shards;
    }

    UInt64 getShard(StringRef key) const
    {
        if constexpr (!sharded)
            return 0;
        return StringRefHash()(key) % configuration.shards;
    }

    template <typename AttributeType, bool is_nullable, typename ValueSetter, typename DefaultValueExtractor>
    void getItemsImpl(
        const Attribute & attribute,
        DictionaryKeysExtractor<dictionary_key_type> & keys_extractor,
        ValueSetter && set_value,
        DefaultValueExtractor & default_value_extractor) const;

    template <typename GetContainersFunc>
    void getAttributeContainers(size_t attribute_index, GetContainersFunc && get_containers_func);

    template <typename GetContainersFunc>
    void getAttributeContainers(size_t attribute_index, GetContainersFunc && get_containers_func) const;

    void resize(size_t added_rows);

    Poco::Logger * log;

    const DictionaryStructure dict_struct;
    const DictionarySourcePtr source_ptr;
    const HashedDictionaryConfiguration configuration;

    std::vector<Attribute> attributes;

    size_t bytes_allocated = 0;
    size_t hierarchical_index_bytes_allocated = 0;
    std::atomic<size_t> element_count = 0;
    size_t bucket_count = 0;
    mutable std::atomic<size_t> query_count{0};
    mutable std::atomic<size_t> found_count{0};

    BlockPtr update_field_loaded_block;
    std::vector<std::unique_ptr<Arena>> string_arenas;
    std::vector<NoAttributesCollectionType> no_attributes_containers;
    DictionaryHierarchicalParentToChildIndexPtr hierarchical_index;
};

extern template class HashedDictionary<DictionaryKeyType::Simple, false, /*sparse*/ false /*sharded*/>;
extern template class HashedDictionary<DictionaryKeyType::Simple, false /*sparse*/, true /*sharded*/>;
extern template class HashedDictionary<DictionaryKeyType::Simple, true /*sparse*/, false /*sharded*/>;
extern template class HashedDictionary<DictionaryKeyType::Simple, true /*sparse*/, true /*sharded*/>;

extern template class HashedDictionary<DictionaryKeyType::Complex, false /*sparse*/, false /*sharded*/>;
extern template class HashedDictionary<DictionaryKeyType::Complex, false /*sparse*/, true /*sharded*/>;
extern template class HashedDictionary<DictionaryKeyType::Complex, true /*sparse*/, false /*sharded*/>;
extern template class HashedDictionary<DictionaryKeyType::Complex, true /*sparse*/, true /*sharded*/>;

}
