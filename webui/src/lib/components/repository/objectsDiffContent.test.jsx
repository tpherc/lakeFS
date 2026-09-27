import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { objects } from '../../api';
import { ObjectsDiff } from './objectsDiff';
import { AppContext } from '../../hooks/appContext';

vi.mock('../../auth/authContext', () => ({
    useAuth: () => ({ onUnauthenticated: vi.fn() }),
}));

vi.mock('../../hooks/repo', () => ({
    useRefs: () => ({
        repo: { id: 'test-repo', storage_id: 'home' },
        loading: false,
        error: null,
    }),
}));

vi.mock('../../hooks/configProvider', () => ({
    useConfigContext: () => ({
        config: {
            storages: [{ blockstore_id: 'home', pre_sign_support_ui: false }],
        },
        loading: false,
        error: null,
    }),
}));

const renderDiff = (diffType) =>
    render(
        <ObjectsDiff
            diffType={diffType}
            repoId="test-repo"
            leftRef="parent-commit"
            rightRef="selected-commit"
            path="pagination-test-001.txt"
        />,
    );

describe('object content diff', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        vi.spyOn(objects, 'getStat').mockResolvedValue({
            size_bytes: 12,
            storage_id: 'home',
        });
        vi.spyOn(objects, 'get').mockImplementation(async (_repo, ref) =>
            ref === 'parent-commit' ? 'old contents\n' : 'new contents\n',
        );
    });

    it.each(['added', 'changed', 'removed'])('renders %s text with the real diff viewer', async (diffType) => {
        renderDiff(diffType);

        const viewer = await screen.findByRole('table');
        if (diffType !== 'added') expect(viewer).toHaveTextContent('old');
        if (diffType !== 'removed') expect(viewer).toHaveTextContent('new');
        expect(objects.getStat).toHaveBeenCalledTimes(diffType === 'changed' ? 2 : 1);
        expect(objects.get).toHaveBeenCalledTimes(diffType === 'changed' ? 2 : 1);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('updates the text viewer when switching between light and dark mode', async () => {
        const themedDiff = (darkMode) => (
            <AppContext.Provider value={{ state: { settings: { darkMode } }, dispatch: vi.fn() }}>
                <ObjectsDiff
                    diffType="changed"
                    repoId="test-repo"
                    leftRef="parent-commit"
                    rightRef="selected-commit"
                    path="pagination-test-001.txt"
                />
            </AppContext.Provider>
        );
        const { rerender } = render(themedDiff(false));
        const viewer = await screen.findByRole('table');
        const lightBackground = getComputedStyle(viewer).backgroundColor;
        expect(lightBackground).not.toBe('');

        rerender(themedDiff(true));
        const darkBackground = getComputedStyle(viewer).backgroundColor;
        expect(darkBackground).not.toBe(lightBackground);
        expect(darkBackground).not.toBe('');
        expect(darkBackground).not.toBe('transparent');
        expect(darkBackground).not.toBe('rgba(0, 0, 0, 0)');

        rerender(themedDiff(false));
        expect(getComputedStyle(viewer).backgroundColor).toBe(lightBackground);
    });

    it('shows a stat failure without fetching object content', async () => {
        objects.getStat.mockRejectedValue(new Error('object metadata unavailable'));

        renderDiff('added');

        expect(await screen.findByRole('alert')).toHaveTextContent('object metadata unavailable');
        expect(objects.get).not.toHaveBeenCalled();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    it('shows a content failure instead of rendering an empty version', async () => {
        objects.get.mockRejectedValue(new Error('object content unavailable'));
        renderDiff('added');
        expect(await screen.findByRole('alert')).toHaveTextContent('object content unavailable');
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    it('waits for both existing versions before rendering a changed object', async () => {
        let finishRight;
        const rightContent = new Promise((resolve) => {
            finishRight = resolve;
        });
        objects.get.mockImplementation(async (_repo, ref) => (ref === 'parent-commit' ? 'old contents' : rightContent));
        renderDiff('changed');
        await waitFor(() => expect(objects.get).toHaveBeenCalledTimes(2));
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
        await act(async () => finishRight('new contents'));
        expect(await screen.findByRole('table')).toHaveTextContent('new');
    });
});
