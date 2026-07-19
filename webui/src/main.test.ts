import { test, expect, vi } from 'vitest';
import { config as apiConfig } from './lib/api';
import {
    getRepositoryStorageConfigs,
    getSelectedRepositoryStorageConfig,
} from './lib/components/repositoryCreateFormStorage';

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

test('config uses one-entry storage config list without legacy storage config', async () => {
    const fetchMock = vi.fn(async () => {
        return new Response(
            JSON.stringify({
                storage_config_list: [
                    {
                        blockstore_id: 'alpha',
                        blockstore_type: 'mem',
                        blockstore_namespace_ValidityRegex: '^mem://',
                        blockstore_namespace_example: 'mem://alpha',
                        import_support: true,
                        import_validity_regex: '^mem://',
                        pre_sign_support: true,
                        pre_sign_support_ui: true,
                    },
                ],
                version_config: {},
                ui_config: {},
            }),
            {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            },
        );
    });
    vi.stubGlobal('fetch', fetchMock);

    try {
        const response = await apiConfig.getConfig();

        expect(fetchMock).toHaveBeenCalledWith(
            '/api/v1/config',
            expect.objectContaining({
                method: 'GET',
            }),
        );
        expect(response.storages).toHaveLength(1);
        expect(response.storages?.[0].blockstore_id).toEqual('alpha');
        expect(response.storages?.[0].warnings).toEqual(['Block adapter mem not usable in production']);
    } finally {
        vi.unstubAllGlobals();
    }
});

export {};
