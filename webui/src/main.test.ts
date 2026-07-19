import { test, expect } from 'vitest';
import {
    getRepositoryStorageConfigs,
    getSelectedRepositoryStorageConfig,
} from './lib/components/repositoryCreateFormStorage';

test('test placeholder', () => {
    expect(1).toEqual(1);
});

test('repository create form warnings follow selected storage config', () => {
    const singleConfig = {
        blockstore_id: 'alpha',
        warnings: ['alpha warning'],
    };
    const storageConfigs = [
        singleConfig,
        {
            blockstore_id: 'beta',
            warnings: ['beta warning'],
        },
    ];

    expect(getRepositoryStorageConfigs(singleConfig, undefined)).toEqual([singleConfig]);
    expect(getSelectedRepositoryStorageConfig(storageConfigs, '')?.warnings).toEqual(['alpha warning']);
    expect(getSelectedRepositoryStorageConfig(storageConfigs, 'beta')?.warnings).toEqual(['beta warning']);
});

export {};
