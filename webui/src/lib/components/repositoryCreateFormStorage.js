export const getRepositoryStorageConfigs = (config, configs) => {
    if (configs?.length) return configs;
    return config ? [config] : [];
};

export const getSelectedRepositoryStorageConfig = (storageConfigs, selectedStorageID) =>
    storageConfigs.find((storageConfig) => storageConfig.blockstore_id === selectedStorageID) ||
    storageConfigs[0] ||
    {};
