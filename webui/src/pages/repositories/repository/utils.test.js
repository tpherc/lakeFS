import { describe, expect, test } from 'vitest';
import { getObjectStorageConfig } from './utils';

const home = { blockstore_id: 'home', pre_sign_support_ui: true };
const source = { blockstore_id: 'source', pre_sign_support_ui: false };

describe('object storage capabilities', () => {
    test('selects the saved source independently of the repository home', () => {
        expect(getObjectStorageConfig([home, source], { storage_id: 'home' }, { storage_id: 'source' })).toBe(source);
    });
    test('retains repository and legacy single-store defaults for absent IDs', () => {
        expect(getObjectStorageConfig([home, source], { storage_id: 'home' }, {})).toBe(home);
        expect(getObjectStorageConfig([home], {}, {})).toBe(home);
    });
    test('does not reinterpret an unknown explicit ID as the remaining store', () => {
        expect(getObjectStorageConfig([home], { storage_id: 'home' }, { storage_id: 'removed' })).toBeNull();
    });
});
