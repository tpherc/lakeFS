import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { objects, refs, repositories } from '../../../lib/api';
import RepositoryObjectsPage from './objects';

const mocks = vi.hoisted(() => ({
    refs: {},
    router: { query: {}, push: vi.fn() },
    outlet: [vi.fn()],
    auth: { onUnauthenticated: vi.fn() },
    config: { config: { storages: [{ pre_sign_support_ui: false, import_support: false }] } },
}));

vi.mock('react-router-dom', async (importOriginal) => ({
    ...(await importOriginal()),
    useOutletContext: () => mocks.outlet,
}));
vi.mock('../../../lib/hooks/router', async (importOriginal) => ({
    ...(await importOriginal()),
    useRouter: () => mocks.router,
}));
vi.mock('../../../lib/hooks/repo', () => ({ useRefs: () => mocks.refs }));
vi.mock('../../../lib/hooks/configProvider', () => ({ useConfigContext: () => mocks.config }));
vi.mock('../../../lib/auth/authContext', () => ({ useAuth: () => mocks.auth }));
vi.mock('../../../lib/components/repository/refDropdown', () => ({ default: () => null }));
vi.mock('../../../lib/components/repository/tree', () => ({
    humanSize: String,
    URINavigator: () => null,
    Tree: ({ results, onDelete, nextPage, onPaginate }) => (
        <section aria-label="Objects">
            {results.length === 0 && <p>No objects</p>}
            {results.map((entry) => (
                <button key={entry.path} onClick={() => onDelete(entry)}>
                    Delete {entry.path}
                </button>
            ))}
            {nextPage && <button onClick={() => onPaginate(nextPage)}>Next page</button>}
        </section>
    ),
}));
vi.mock('../../../lib/components/repository/changes', () => ({
    ChangesTreeContainer: ({ results }) => <section aria-label="Changes">{results.length} changes</section>,
}));
vi.mock('./objectViewer', () => ({
    getFileExtension: () => 'md',
    FileContents: ({ repoId, reference, path }) => (
        <article aria-label="README">
            {repoId}/{reference.id}/{path}
        </article>
    ),
}));

const deferred = () => {
    let resolve;
    const promise = new Promise((resolvePromise) => {
        resolve = resolvePromise;
    });
    return { promise, resolve };
};
const listing = (path = 'old.csv') => ({
    results: path ? [{ path, path_type: 'object' }] : [],
    pagination: { has_more: false },
});
const page = () => (
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <RepositoryObjectsPage />
    </MemoryRouter>
);
const frame = (container) => container.querySelector('[aria-busy]');
let measuredHeight;
let resizeCallbacks;

beforeEach(() => {
    mocks.refs = {
        repo: { id: 'repo', storage_namespace: 'local://repo' },
        reference: { id: 'main', type: 'branch' },
        loading: false,
        error: null,
    };
    mocks.router.query = {};
    mocks.router.push.mockReset();
    mocks.router.push.mockImplementation(({ query }) => {
        mocks.router.query = query;
    });
    vi.spyOn(repositories, 'get').mockResolvedValue(mocks.refs.repo);
    vi.spyOn(refs, 'changes').mockResolvedValue({ results: [], pagination: { has_more: false } });
    vi.spyOn(objects, 'getStat').mockResolvedValue({ content_type: 'text/markdown', size_bytes: 4 });
    vi.spyOn(objects, 'list').mockResolvedValue(listing());
    vi.spyOn(objects, 'delete').mockResolvedValue(undefined);
    measuredHeight = 480;
    resizeCallbacks = [];
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(
        () => new DOMRect(0, 0, 800, measuredHeight),
    );
    vi.stubGlobal(
        'ResizeObserver',
        class {
            constructor(callback) {
                resizeCallbacks.push(callback);
            }
            observe() {}
            disconnect() {}
        },
    );
});

afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
});

describe('object listing loading', () => {
    it('loads README independently and keeps its node when the listing settles', async () => {
        const pending = deferred();
        objects.list.mockReturnValue(pending.promise);
        const { container } = render(page());
        const readme = await screen.findByRole('article', { name: 'README' });

        expect(frame(container)).toHaveAttribute('aria-busy', 'true');
        expect(frame(container).style.minHeight).toBe('12rem');
        expect(screen.queryByRole('button', { name: 'Delete old.csv' })).not.toBeInTheDocument();

        await act(async () => pending.resolve(listing()));
        expect(screen.getByRole('button', { name: 'Delete old.csv' })).toBeInTheDocument();
        expect(frame(container)).toHaveAttribute('aria-busy', 'false');
        expect(frame(container).style.minHeight).toBe('');
        expect(screen.getByRole('article', { name: 'README' })).toBe(readme);
        expect(objects.getStat).toHaveBeenCalledTimes(1);
    });

    it('keeps the latest measured height during refresh while removing old row actions', async () => {
        const { container } = render(page());
        const oldAction = await screen.findByRole('button', { name: 'Delete old.csv' });
        measuredHeight = 620;
        act(() => resizeCallbacks.at(-1)());
        const pending = deferred();
        objects.list.mockReturnValue(pending.promise);

        fireEvent.click(oldAction);
        await waitFor(() => expect(frame(container)).toHaveAttribute('aria-busy', 'true'));
        expect(frame(container)).toHaveStyle({ minHeight: '620px' });
        expect(oldAction).not.toBeInTheDocument();
        expect(objects.delete).toHaveBeenCalledExactlyOnceWith('repo', 'main', 'old.csv');

        await act(async () => pending.resolve(listing('new.csv')));
        expect(screen.getByRole('button', { name: 'Delete new.csv' })).toBeInTheDocument();
        expect(frame(container).style.minHeight).toBe('');
    });

    it.each([
        ['path', () => (mocks.router.query = { path: 'folder/' })],
        ['page', () => (mocks.router.query = { after: 'old.csv' })],
        ['reference', () => (mocks.refs.reference = { id: 'feature', type: 'branch' })],
        ['repository', () => (mocks.refs.repo = { ...mocks.refs.repo, id: 'other' })],
        ['reference type', () => (mocks.refs.reference = { id: 'main', type: 'commit' }), 'tag'],
    ])(
        'resets the listing height and old actions when the %s changes',
        async (_identity, navigate, initialType = 'branch') => {
            mocks.refs.reference.type = initialType;
            const { container, rerender } = render(page());
            const oldAction = await screen.findByRole('button', { name: 'Delete old.csv' });
            const pending = deferred();
            objects.list.mockReturnValue(pending.promise);

            navigate();
            rerender(page());
            expect(frame(container)).toHaveAttribute('aria-busy', 'true');
            expect(frame(container).style.minHeight).toBe('12rem');
            expect(oldAction).not.toBeInTheDocument();

            await act(async () => pending.resolve(listing('new.csv')));
            expect(screen.getByRole('button', { name: 'Delete new.csv' })).toBeInTheDocument();
            expect(frame(container).style.minHeight).toBe('');
        },
    );

    it('preserves README and its request across same-folder pagination', async () => {
        objects.list.mockResolvedValue({ ...listing(), pagination: { has_more: true, next_offset: 'old.csv' } });
        const { container, rerender } = render(page());
        const nextPage = await screen.findByRole('button', { name: 'Next page' });
        const readme = screen.getByRole('article', { name: 'README' });
        const pending = deferred();
        objects.list.mockReturnValue(pending.promise);

        fireEvent.click(nextPage);
        rerender(page());
        expect(mocks.router.push).toHaveBeenCalledWith({
            pathname: '/repositories/:repoId/objects',
            params: { repoId: 'repo' },
            query: { after: 'old.csv', ref: 'main' },
        });
        expect(frame(container).style.minHeight).toBe('12rem');
        expect(screen.getByRole('article', { name: 'README' })).toBe(readme);
        expect(objects.getStat).toHaveBeenCalledTimes(1);

        await act(async () => pending.resolve(listing('next.csv')));
        expect(screen.getByRole('article', { name: 'README' })).toBe(readme);
        expect(objects.getStat).toHaveBeenCalledTimes(1);
    });

    it('releases loading space for an empty listing', async () => {
        objects.list.mockResolvedValue(listing(''));
        const { container } = render(page());

        expect(await screen.findByText('No objects')).toBeInTheDocument();
        expect(frame(container)).toHaveAttribute('aria-busy', 'false');
        expect(frame(container).style.minHeight).toBe('');
        expect(screen.getByRole('article', { name: 'README' })).toBeInTheDocument();
    });

    it('shows listing errors without hiding README or leaving reserved loading space', async () => {
        objects.list.mockRejectedValue(new Error('Listing unavailable'));
        const { container } = render(page());

        expect(await screen.findByRole('alert')).toHaveTextContent('Listing unavailable');
        expect(frame(container)).toBeNull();
        expect(screen.getByRole('article', { name: 'README' })).toBeInTheDocument();
        expect(screen.queryByText('Loading...')).not.toBeInTheDocument();
    });

    it('preserves README when switching to empty changes and back to objects', async () => {
        refs.changes.mockResolvedValue({ results: [{ path: 'old.csv', type: 'changed' }] });
        const { container } = render(page());
        const toggle = await screen.findByRole('button', { name: 'Uncommitted Changes' });
        const readme = screen.getByRole('article', { name: 'README' });
        const pending = deferred();
        refs.changes.mockReturnValue(pending.promise);

        fireEvent.click(toggle);
        expect(frame(container).style.minHeight).toBe('12rem');
        expect(screen.queryByRole('button', { name: 'Delete old.csv' })).not.toBeInTheDocument();
        expect(screen.getByRole('article', { name: 'README' })).toBe(readme);

        await act(async () => pending.resolve({ results: [], pagination: { has_more: false } }));
        expect(screen.getByRole('heading', { name: 'No Changes Here' })).toBeInTheDocument();
        expect(frame(container).style.minHeight).toBe('');
        expect(screen.getByRole('article', { name: 'README' })).toBe(readme);

        fireEvent.click(screen.getByRole('button', { name: 'See All Objects' }));
        await screen.findByRole('button', { name: 'Delete old.csv' });
        expect(screen.getByRole('article', { name: 'README' })).toBe(readme);
        expect(objects.getStat).toHaveBeenCalledTimes(1);
    });
});
