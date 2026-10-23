#pragma once

#include <Storages/IStorage.h>
#include <Storages/StorageInMemoryMetadata.h>
#include <Interpreters/DatabaseCatalog.h>
#include <Access/Common/AccessType.h>
#include <optional>

namespace DB
{

class StorageAlias final : public IStorage, WithContext
{
public:
    struct TargetAccess
    {
        ContextPtr context;
        AccessType access_type;
        Names column_names = {};
    };

    StorageAlias(
        const StorageID & table_id_,
        ContextPtr context_,
        const String & target_database_,
        const String & target_table_);

    std::string getName() const override { return "Alias"; }

    bool isMergeTree() const override;

    bool readsFromOtherTables() const override { return true; }
    std::vector<StoragePtr> getUnderlyingStorages() const override
    {
        if (auto target = tryGetTargetTableWithoutAccessCheck())
            return {target};
        return {};
    }

    /// An `Alias` has no data of its own, so a bulk `TRUNCATE ALL TABLES` must skip it.
    /// Only the bulk paths consult this; an explicit `TRUNCATE TABLE <alias>` still truncates the target.
    bool supportsTruncate() const override { return false; }

    /// The alias holds no metadata of its own, so the answer is the target's. Without this a
    /// unique-key table read through an alias would look unconstrained to the planner.
    bool hasUniqueKey() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->hasUniqueKey();
    }

    /// Resolves the target, authorizing `access` against the target's name first, so that which error
    /// comes back does not tell a denied user whether the target exists.
    StoragePtr getTargetTable(const TargetAccess & access) const;

    /// Resolves the target with no authorization at all: for callers holding no query context, and for
    /// those that authorize it themselves. Spelling it out is what keeps them findable.
    StoragePtr getTargetTableWithoutAccessCheck() const;
    StoragePtr tryGetTargetTableWithoutAccessCheck() const { return DatabaseCatalog::instance().tryGetTable(StorageID(target_database, target_table), getContext()); }

    /// Returns whether the current user has the specified access to every table this alias resolves
    /// through, i.e. the whole chain when the target is itself an Alias. For callers that read metadata.
    /// An empty `column_name` represents table-level access.
    bool isTargetTableGranted(ContextPtr query_context, AccessType access_type, const String & column_name) const;

    /// Same, for the target named in this alias's own definition only. For callers that expose that
    /// definition and resolve nothing through it.
    bool isDeclaredTargetGranted(ContextPtr query_context, AccessType access_type, const String & column_name) const;

    /// Returns the subset of `column_names` the current user has this access to on every table this
    /// alias resolves through. Resolves the chain once, whatever the grants look like.
    NameSet filterColumnsGrantedThroughChain(ContextPtr query_context, AccessType access_type, const Names & column_names) const;

    /// Read from target table
    void read(
        QueryPlan & query_plan,
        const Names & column_names,
        const StorageSnapshotPtr & storage_snapshot,
        SelectQueryInfo & query_info,
        ContextPtr local_context,
        QueryProcessingStage::Enum processed_stage,
        size_t max_block_size,
        size_t num_streams) override;

    /// Write to target table
    SinkToStoragePtr write(
        const ASTPtr & query,
        const StorageMetadataPtr & metadata_snapshot,
        ContextPtr local_context,
        bool async_insert) override;

    /// Distributed write to target table
    std::optional<QueryPipeline> distributedWrite(const ASTInsertQuery & query, ContextPtr local_context) override;

    void checkAlterIsPossible(const AlterCommands & commands, ContextPtr local_context) const override { getTargetTableWithoutAccessCheck()->checkAlterIsPossible(commands, local_context); }

    /// Alter target table
    void alter(
        const AlterCommands & params,
        ContextPtr local_context,
        AlterLockHolder & table_lock_holder,
        DDLGuardPtr & ddl_guard) override;

    /// Truncate target table
    void truncate(
        const ASTPtr & query,
        const StorageMetadataPtr & metadata_snapshot,
        ContextPtr local_context,
        TableExclusiveLockHolder & table_lock_holder) override;

    /// Optimize target table
    bool optimize(
        const ASTPtr & query,
        const StorageMetadataPtr & metadata_snapshot,
        const ASTPtr & partition,
        bool final,
        bool deduplicate,
        const Names & deduplicate_by_columns,
        bool cleanup,
        ContextPtr local_context) override;

    /// Alter partition on target table
    Pipe alterPartition(
        const StorageMetadataPtr & metadata_snapshot,
        const PartitionCommands & commands,
        ContextPtr local_context) override;

    void checkAlterPartitionIsPossible(
        const PartitionCommands & commands,
        const StorageMetadataPtr & metadata_snapshot,
        const Settings & settings,
        ContextPtr local_context) const override;

    void checkMutationIsPossible(const MutationCommands & commands, const Settings & settings) const override { getTargetTableWithoutAccessCheck()->checkMutationIsPossible(commands, settings); }

    void checkInsertIsAllowed(ContextPtr local_context) const override { getTargetTableWithoutAccessCheck()->checkInsertIsAllowed(local_context); }

    /// Mutate target table
    void mutate(
        const MutationCommands & commands,
        ContextPtr local_context) override;

    /// Lightweight update on target table
    QueryPipeline updateLightweight(const MutationCommands & commands, ContextPtr local_context) override;

    CancellationCode killMutation(const String & mutation_id) override;
    void waitForMutation(const String & mutation_id, bool wait_for_another_mutation) override;
    void setMutationCSN(const String & mutation_id, UInt64 csn) override;

    void updateExternalDynamicMetadataIfExists(ContextPtr local_context) override;
    void checkTableCanBeDropped(ContextPtr /*query_context*/) const override {}

    StorageMetadataHandle getInMemoryMetadataPtr(ContextPtr query_context, bool bypass_metadata_cache) const override;

    StorageSnapshotPtr getStorageSnapshot(const StorageMetadataPtr & metadata_snapshot, ContextPtr query_context) const override;
    StorageSnapshotPtr getStorageSnapshotWithoutData(const StorageMetadataPtr & metadata_snapshot, ContextPtr query_context) const override;

    /// Capabilities that validate a user-requested operation resolve the target table and report UNKNOWN_TABLE for a
    /// broken Alias. Advisory capability probes used for optimization, routing, execution strategy, or system-table
    /// metadata fail closed (return false).
    bool supportsSampling() const override { return getTargetTableWithoutAccessCheck()->supportsSampling(); }
    bool supportsFinal() const override { return getTargetTableWithoutAccessCheck()->supportsFinal(); }
    bool supportsSubcolumns() const override { return getTargetTableWithoutAccessCheck()->supportsSubcolumns(); }
    bool supportsColumnsWithDynamicStructure() const override { return getTargetTableWithoutAccessCheck()->supportsColumnsWithDynamicStructure(); }
    bool supportsPrewhere() const override { return getTargetTableWithoutAccessCheck()->supportsPrewhere(); }
    std::optional<NameSet> supportedPrewhereColumns() const override { return getTargetTableWithoutAccessCheck()->supportedPrewhereColumns(); }
    bool supportedPrewhereColumnsIncludeSubcolumns() const override { return getTargetTableWithoutAccessCheck()->supportedPrewhereColumnsIncludeSubcolumns(); }
    bool canMoveConditionsToPrewhere() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->canMoveConditionsToPrewhere();
    }
    bool supportsOptimizationToSubcolumns() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->supportsOptimizationToSubcolumns();
    }
    bool supportsOptimizationToTupleElementSubcolumns() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->supportsOptimizationToTupleElementSubcolumns();
    }
    bool supportsParallelInsert() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->supportsParallelInsert();
    }
    bool supportsDeduplication() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->supportsDeduplication();
    }
    bool supportsTransactions() const override { return getTargetTableWithoutAccessCheck()->supportsTransactions(); }
    bool noPushingToViewsOnInserts() const override { return getTargetTableWithoutAccessCheck()->noPushingToViewsOnInserts(); }
    bool hasEvenlyDistributedRead() const override { return getTargetTableWithoutAccessCheck()->hasEvenlyDistributedRead(); }
    bool prefersLargeBlocks() const override { return getTargetTableWithoutAccessCheck()->prefersLargeBlocks(); }
    bool areAsynchronousInsertsEnabled() const override { return getTargetTableWithoutAccessCheck()->areAsynchronousInsertsEnabled(); }
    bool isRemote() const override { return getTargetTableWithoutAccessCheck()->isRemote(); }
    bool readRequiresAnalyzedQuery() const override { return getTargetTableWithoutAccessCheck()->readRequiresAnalyzedQuery(); }
    bool isSharedStorage() const override { return getTargetTableWithoutAccessCheck()->isSharedStorage(); }
    bool supportsReplication() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->supportsReplication();
    }
    bool supportsLightweightDelete() const override { return getTargetTableWithoutAccessCheck()->supportsLightweightDelete(); }
    std::expected<void, PreformattedMessage> supportsLightweightUpdate() const override
    {
        return getTargetTableWithoutAccessCheck()->supportsLightweightUpdate();
    }
    bool supportsDelete() const override { return getTargetTableWithoutAccessCheck()->supportsDelete(); }
    bool hasProjection() const override { return getTargetTableWithoutAccessCheck()->hasProjection(); }
    bool supportsSparseSerialization() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        return target && target->supportsSparseSerialization();
    }
    bool supportsTrivialCountOptimization(const StorageSnapshotPtr & storage_snapshot, ContextPtr query_context) const override;
    bool supportsPartitionBy() const override { return getTargetTableWithoutAccessCheck()->supportsPartitionBy(); }
    bool supportsTTL() const override { return getTargetTableWithoutAccessCheck()->supportsTTL(); }
    bool supportsStatistics() const override { return getTargetTableWithoutAccessCheck()->supportsStatistics(); }

    QueryProcessingStage::Enum getQueryProcessingStage(
        ContextPtr local_context,
        QueryProcessingStage::Enum to_stage,
        const StorageSnapshotPtr & storage_snapshot,
        SelectQueryInfo & query_info) const override;

    Strings getDataPaths() const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->getDataPaths() : Strings{}; }
    std::optional<Strings> tryGetDataPaths() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        if (!target)
            return std::nullopt;

        return target->getDataPaths();
    }

    /// Alias does not store data on disk
    bool storesDataOnDisk() const override { return false; }

    StoragePolicyPtr getStoragePolicy() const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->getStoragePolicy() : StoragePolicyPtr{}; }
    std::optional<StoragePolicyPtr> tryGetStoragePolicy() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        if (!target)
            return std::nullopt;

        return target->getStoragePolicy();
    }

    SerializationInfoByName getSerializationHints() const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->getSerializationHints() : IStorage::getSerializationHints(); }
    std::optional<SerializationInfoByName> tryGetSerializationHints() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        if (!target)
            return std::nullopt;

        return target->getSerializationHints();
    }

    /// An alias runs no background activity of its own, and this has no query context to authorize the
    /// target with, so the lock has to be taken on the target under its own name.
    ActionLock getActionLock(StorageActionBlockType /*type*/) override { return {}; }

    TableLockHolder lockForShare(const String & query_id, const std::chrono::milliseconds & acquire_timeout) const { return getTargetTableWithoutAccessCheck()->lockForShare(query_id, Poco::Timespan(acquire_timeout.count() * 1000)); }
    TableLockHolder tryLockForShare(const String & query_id, const std::chrono::milliseconds & acquire_timeout) const
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        if (!target)
            return nullptr;

        return target->tryLockForShare(query_id, Poco::Timespan(acquire_timeout.count() * 1000));
    }

    std::optional<UInt64> totalRows(ContextPtr query_context) const override;
    std::optional<UInt64> totalBytes(ContextPtr query_context) const override;
    std::optional<UInt64> totalBytesUncompressed(const Settings & settings) const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->totalBytesUncompressed(settings) : std::optional<UInt64>{}; }
    std::optional<UInt64> lifetimeRows() const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->lifetimeRows() : std::optional<UInt64>{}; }
    std::optional<std::optional<UInt64>> tryLifetimeRows() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        if (!target)
            return std::nullopt;

        return target->lifetimeRows();
    }

    std::optional<UInt64> lifetimeBytes() const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->lifetimeBytes() : std::optional<UInt64>{}; }
    std::optional<std::optional<UInt64>> tryLifetimeBytes() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        if (!target)
            return std::nullopt;

        return target->lifetimeBytes();
    }

    ColumnSizeByName getColumnSizes() const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->getColumnSizes() : ColumnSizeByName{}; }
    ColumnSizeByName getColumnSizes(const Names & columns, bool calculate_subcolumn_sizes) const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->getColumnSizes(columns, calculate_subcolumn_sizes) : ColumnSizeByName{}; }
    std::optional<ColumnSizeByName> tryGetColumnSizes() const override
    {
        auto target = tryGetTargetTableWithoutAccessCheck();
        if (!target)
            return std::nullopt;

        return target->getColumnSizes();
    }

    IndexSizeByName getSecondaryIndexSizes() const override { auto target = tryGetTargetTableWithoutAccessCheck(); return target ? target->getSecondaryIndexSizes() : IndexSizeByName{}; }

    DataValidationTasksPtr getCheckTaskList(const CheckTaskFilter & filter, ContextPtr query_context) override;
    std::optional<CheckResult> checkDataNext(DataValidationTasksPtr & check_task_list) override;

    CancellationCode killPartMoveToShard(const UUID & task_uuid) override;

    /// These operations are not proxied (executed on alias itself)
    /// Drop alias, not the target table
    void drop() override {}

    /// Rename alias, not the target table
    void rename(const String & new_path_to_table_data, const StorageID & new_table_id) override;

protected:
    String target_database;
    String target_table;
};

}
