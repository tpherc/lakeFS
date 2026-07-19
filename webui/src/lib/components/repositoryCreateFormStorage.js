export const getRepositoryStorageConfigs = (config, configs) => (configs?.length ? configs : config ? [config] : []);

export const getSelectedRepositoryStorageConfig = (storageConfigs, selectedStorageID) =>
    storageConfigs.find((storageConfig) => storageConfig.blockstore_id === selectedStorageID) ||
    storageConfigs[0] ||
    {};
