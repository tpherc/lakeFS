import React, { createContext } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, test, vi } from 'vitest';
import { ObjectsDiff } from './objectsDiff';
import { objects } from '../../api';

vi.mock('../../auth/authContext', () => ({ useAuth: () => ({ onUnauthenticated: vi.fn() }) }));
vi.mock('../../hooks/repo', () => ({ useRefs: () => ({ repo: { storage_id: 'home' } }) }));
vi.mock('../../hooks/configProvider', () => ({
    useConfigContext: () => ({
        config: {
            storages: [
                { blockstore_id: 'home', pre_sign_support_ui: true },
                { blockstore_id: 'foreign', pre_sign_support_ui: false },
            ],
        },
    }),
}));
vi.mock('../../hooks/appContext', () => ({ AppContext: createContext({ state: { settings: {} } }) }));
vi.mock('./tree', () => ({ humanSize: (size) => String(size) }));
vi.mock('react-diff-viewer-continued', () => ({
    default: ({ oldValue, newValue }) => (
        <div>
            {oldValue} / {newValue}
        </div>
    ),
    DiffMethod: { WORDS: 'words' },
}));
vi.mock('../../api', async (importOriginal) => ({
    ...(await importOriginal()),
    objects: { getStat: vi.fn(), get: vi.fn() },
}));

beforeEach(() => {
    vi.clearAllMocks();
    objects.getStat.mockImplementation(async (_repo, ref) => ({
        storage_id: ref === 'before' ? 'home' : 'foreign',
        size_bytes: 10,
    }));
    objects.get.mockImplementation(async (_repo, ref) => ref);
});

test('diff uses each version binding without fetching its stats twice', async () => {
    render(<ObjectsDiff diffType="changed" repoId="repo" leftRef="before" rightRef="after" path="file.txt" />);
    await screen.findByText('before / after');
    expect(objects.get).toHaveBeenCalledWith('repo', 'before', 'file.txt', true);
    expect(objects.get).toHaveBeenCalledWith('repo', 'after', 'file.txt', false);
    expect(objects.getStat).toHaveBeenCalledTimes(2);
});

test('image diff signs each URL independently', async () => {
    render(<ObjectsDiff diffType="changed" repoId="repo" leftRef="before" rightRef="after" path="image.png" />);
    await waitFor(() => expect(screen.getByAltText('old').src).toContain('presign=true'));
    expect(screen.getByAltText('new').src).toContain('presign=false');
});
