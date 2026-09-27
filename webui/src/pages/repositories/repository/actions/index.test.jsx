import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Outlet, Route, Routes } from 'react-router-dom';

import RepositoryActionsPage from './index';

const mocks = vi.hoisted(() => ({
    onUnauthenticated: vi.fn(),
    setActivePage: vi.fn(),
}));

vi.mock('../../../../lib/auth/authContext', () => ({
    useAuth: () => ({ onUnauthenticated: mocks.onUnauthenticated }),
}));

vi.mock('../../../../lib/hooks/repo', () => ({
    useRefs: () => ({ repo: { id: 'test-repo' }, loading: false, error: null }),
}));

vi.mock('../fileRenderers/simple', () => ({
    TextRenderer: ({ text }) => <pre>{text}</pre>,
}));

const jsonResponse = (body, status = 200) =>
    new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });

const renderActionsPage = (query = '') =>
    render(
        <MemoryRouter initialEntries={[`/repositories/test-repo/actions${query}`]}>
            <Routes>
                <Route element={<Outlet context={[mocks.setActivePage]} />}>
                    <Route path="/repositories/:repoId/actions" element={<RepositoryActionsPage />} />
                </Route>
            </Routes>
        </MemoryRouter>,
    );

describe('repository actions', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.stubGlobal('fetch', vi.fn());
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it.each([401, 403, 500])('shows a failed run listing (%i) without crashing', async (status) => {
        fetch.mockResolvedValue(jsonResponse({ message: 'access denied' }, status));

        renderActionsPage();

        expect(await screen.findByRole('alert')).toHaveTextContent('access denied');
        expect(screen.getByRole('button')).toBeEnabled();
        expect(screen.queryByText('No actions configured yet')).not.toBeInTheDocument();
        expect(screen.queryByText(/Actions can be configured/)).not.toBeInTheDocument();
        expect(mocks.onUnauthenticated).not.toHaveBeenCalled();
    });

    it('retries a failed listing with the current filters and pagination', async () => {
        const user = userEvent.setup();
        const commit = '0123456789abcdef';
        fetch.mockResolvedValueOnce(jsonResponse({ message: 'access denied' }, 401)).mockResolvedValueOnce(
            jsonResponse({
                results: [
                    {
                        run_id: 'run-123',
                        event_type: 'pre-commit',
                        branch: 'main',
                        start_time: 1700000000,
                        commit_id: commit,
                        status: 'completed',
                    },
                ],
                pagination: { has_more: false },
            }),
        );

        renderActionsPage(`?branch=main&commit=${commit}&after=previous-run`);

        expect(await screen.findByRole('alert')).toHaveTextContent('access denied');
        expect(screen.getByRole('button', { name: 'main' })).toBeEnabled();
        expect(screen.getByRole('button', { name: commit.slice(0, 12) })).toBeEnabled();
        await user.click(screen.getByRole('button', { name: '' }));

        expect(await screen.findByRole('link', { name: 'run-123' })).toHaveAttribute(
            'href',
            '/repositories/test-repo/actions/run-123',
        );
        expect(screen.getByRole('table')).toHaveTextContent('pre-commit');
        expect(screen.getByText(/Actions can be configured/)).toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(fetch).toHaveBeenCalledTimes(2);
        for (const [url] of fetch.mock.calls) {
            expect(url).toBe(
                `/api/v1/repositories/test-repo/actions/runs?branch=main&commit=${commit}&after=previous-run&amount=100`,
            );
        }
    });

    it('shows the empty state after a successful listing with no runs', async () => {
        fetch.mockResolvedValue(jsonResponse({ results: [], pagination: { has_more: false } }));

        renderActionsPage();

        expect(await screen.findByRole('heading', { name: 'No actions configured yet' })).toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
});
