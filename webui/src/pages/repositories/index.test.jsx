import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, test, vi } from 'vitest';

import RepositoriesPage from './index';

const mocks = vi.hoisted(() => ({
    configContext: {
        config: null,
        error: null,
        loading: true,
    },
    pagination: {
        results: [],
        loading: true,
        error: null,
        nextPage: false,
    },
    router: {
        query: {},
        push: vi.fn(),
    },
    createRepository: vi.fn(),
}));

vi.mock('../../lib/hooks/configProvider', () => ({
    useConfigContext: () => mocks.configContext,
}));

vi.mock('../../lib/hooks/api', () => ({
    useAPIWithPagination: () => mocks.pagination,
}));

vi.mock('../../lib/hooks/router', () => ({
    useRouter: () => mocks.router,
}));

vi.mock('../../lib/api', () => ({
    repositories: {
        create: (...args) => mocks.createRepository(...args),
        list: vi.fn(),
    },
}));

beforeEach(() => {
    mocks.configContext.config = null;
    mocks.configContext.error = null;
    mocks.configContext.loading = true;
    mocks.pagination.results = [];
    mocks.pagination.loading = true;
    mocks.pagination.error = null;
    mocks.pagination.nextPage = false;
    mocks.router.query = {};
    mocks.router.push.mockReset();
    mocks.createRepository.mockReset();
});

test('repositories page renders while configuration is loading', () => {
	expect(() => render(<RepositoriesPage />)).not.toThrow();
	expect(screen.getAllByText('Loading...')).not.toHaveLength(0);
});

test('sample repository creation includes the selected storage backend', async () => {
    const user = userEvent.setup();
    mocks.configContext.config = {
        storages: [
            {
                blockstore_id: 'alpha',
                blockstore_type: 'local',
            },
        ],
    };
    mocks.configContext.loading = false;
    mocks.pagination.loading = false;
    mocks.createRepository.mockResolvedValue({});

    render(<RepositoriesPage />);

    await user.click(screen.getByText('Create Sample Repository'));

    await waitFor(() => {
        expect(mocks.createRepository).toHaveBeenCalledWith({
            name: 'quickstart',
            storage_id: 'alpha',
            storage_namespace: 'local://quickstart',
            default_branch: 'main',
            sample_data: true,
        });
    });
});
