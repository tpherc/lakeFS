import React from 'react';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { MemoryRouter } from 'react-router-dom';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, test, vi } from 'vitest';

import { TreeContainer } from './objects';
import { refs } from '../../../lib/api';

const homeConfig = { blockstore_id: 'home', pre_sign_support: true, pre_sign_support_ui: true };
const sourceConfig = { blockstore_id: 'source', pre_sign_support: false, pre_sign_support_ui: false };

vi.mock('./objectViewer', () => ({ FileContents: () => null, getFileExtension: () => 'txt' }));
vi.mock('../../../lib/auth/authContext', () => ({ useAuth: () => ({ onUnauthenticated: vi.fn() }) }));
vi.mock('../../../lib/hooks/configProvider', () => ({
    useConfigContext: () => ({ config: { storages: [homeConfig, sourceConfig] } }),
}));

dayjs.extend(relativeTime);

afterEach(() => vi.restoreAllMocks());

test('mixed object listing stays unsigned while download links use each source capability', async () => {
    const user = userEvent.setup();
    vi.spyOn(refs, 'changes').mockResolvedValue({ results: [] });
    const listingRequests = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
        const url = new URL(input, 'http://localhost');
        expect(url.pathname).toBe('/api/v1/repositories/repo/refs/main/objects/ls');
        listingRequests.push(url);
        if (url.searchParams.get('presign') === 'true') {
            return new Response(JSON.stringify({ message: 'source backend does not support signing' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' },
            });
        }
        return new Response(
            JSON.stringify({
                results: [
                    {
                        path: 'home.txt',
                        path_type: 'object',
                        storage_id: 'home',
                        physical_address: 's3://home/object',
                        size_bytes: 4,
                        mtime: 1,
                    },
                    {
                        path: 'source.txt',
                        path_type: 'object',
                        storage_id: 'source',
                        physical_address: 'gs://raw/object',
                        size_bytes: 4,
                        mtime: 1,
                    },
                ],
                pagination: { has_more: false },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
    });
    render(
        <MemoryRouter>
            <TreeContainer
                config={homeConfig}
                repo={{ id: 'repo', storage_id: 'home' }}
                reference={{ id: 'main', type: 'branch' }}
                path=""
                after=""
                onPaginate={vi.fn()}
                onRefresh={vi.fn()}
                onUpload={vi.fn()}
                onImport={vi.fn()}
                refreshToken={false}
                showChangesOnly={false}
                toggleShowChangesOnly={vi.fn()}
            />
        </MemoryRouter>,
    );

    const homeRow = (await screen.findByRole('link', { name: 'home.txt' })).closest('tr');
    const sourceRow = screen.getByRole('link', { name: 'source.txt' }).closest('tr');
    expect(listingRequests).toHaveLength(1);
    expect(listingRequests[0].searchParams.get('presign')).toBe('false');

    await user.click(within(homeRow).getByRole('button'));
    const homeDownload = within(homeRow).getByRole('link', { name: 'Download' });
    expect(new URL(homeDownload.href).searchParams.get('presign')).toBe('true');
    expect(within(homeRow).getByText('Copy Presigned URL')).toBeVisible();

    await user.click(within(sourceRow).getByRole('button'));
    const sourceDownload = within(sourceRow).getByRole('link', { name: 'Download' });
    expect(new URL(sourceDownload.href).searchParams.get('presign')).toBe('false');
    expect(within(sourceRow).queryByText('Copy Presigned URL')).not.toBeInTheDocument();
});
