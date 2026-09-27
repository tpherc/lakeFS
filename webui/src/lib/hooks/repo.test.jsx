import React from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { branches, commits, repositories, tags, BareRepositoryError, NotFoundError } from '../api';
import { RefTypeBranch, RefTypeCommit, RefTypeTag } from '../../constants';
import { RefContextProvider, useRefs } from './repo';

const mocks = vi.hoisted(() => ({
    router: { params: { repoId: 'repo' }, query: {} },
    onUnauthenticated: vi.fn(),
}));

vi.mock('./router', () => ({ useRouter: () => mocks.router }));
vi.mock('../auth/authContext', () => ({
    useAuth: () => ({ onUnauthenticated: mocks.onUnauthenticated }),
}));

const repo = { id: 'repo', default_branch: 'main' };
const wrapper = ({ children }) => <RefContextProvider>{children}</RefContextProvider>;

const deferred = () => {
    let resolve;
    const promise = new Promise((resolvePromise) => {
        resolve = resolvePromise;
    });
    return { promise, resolve };
};

beforeEach(() => {
    mocks.router.query = {};
    mocks.onUnauthenticated.mockReset();
    vi.spyOn(repositories, 'get').mockResolvedValue(repo);
    vi.spyOn(branches, 'get').mockImplementation(async (_repoId, refId) => ({ id: refId }));
    vi.spyOn(branches, 'list').mockResolvedValue({ results: [{ id: 'main' }] });
    vi.spyOn(tags, 'get').mockRejectedValue(new NotFoundError('tag not found'));
    vi.spyOn(commits, 'get').mockRejectedValue(new NotFoundError('commit not found'));
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('RefContextProvider', () => {
    it.each([{}, { ref: 'main' }, { ref: 'release', compare: 'release' }])(
        'resolves matching effective references only once for %j',
        async (query) => {
            mocks.router.query = query;
            const { result } = renderHook(useRefs, { wrapper });

            await waitFor(() => expect(result.current.loading).toBe(false));

            const reference = { id: query.ref || 'main', type: RefTypeBranch };
            expect(result.current).toEqual({ loading: false, error: null, repo, reference, compare: reference });
            expect(branches.get).toHaveBeenCalledExactlyOnceWith('repo', reference.id);
        },
    );

    it('starts distinct reference lookups together and waits for both', async () => {
        mocks.router.query = { ref: 'feature', compare: 'main' };
        const reference = deferred();
        const comparison = deferred();
        branches.get.mockImplementation((_repoId, refId) =>
            refId === 'feature' ? reference.promise : comparison.promise,
        );
        const { result } = renderHook(useRefs, { wrapper });

        await waitFor(() => expect(branches.get).toHaveBeenCalledTimes(2));
        expect(branches.get).toHaveBeenCalledWith('repo', 'feature');
        expect(branches.get).toHaveBeenCalledWith('repo', 'main');
        expect(result.current.loading).toBe(true);

        await act(async () => comparison.resolve({ id: 'main' }));
        expect(result.current.loading).toBe(true);

        await act(async () => reference.resolve({ id: 'feature' }));
        expect(result.current).toEqual({
            loading: false,
            error: null,
            repo,
            reference: { id: 'feature', type: RefTypeBranch },
            compare: { id: 'main', type: RefTypeBranch },
        });
    });

    it('reports a failed comparison while the other lookup is pending', async () => {
        mocks.router.query = { ref: 'feature', compare: 'main' };
        const reference = deferred();
        const failure = new Error('lookup failed');
        branches.get.mockImplementation((_repoId, refId) =>
            refId === 'feature' ? reference.promise : Promise.reject(failure),
        );
        const { result } = renderHook(useRefs, { wrapper });

        await waitFor(() => expect(result.current.error).toBe(failure));
        expect(result.current).toEqual({ loading: false, error: failure, repo: null, reference: null, compare: null });
        expect(tags.get).not.toHaveBeenCalled();
        expect(commits.get).not.toHaveBeenCalled();

        await act(async () => reference.resolve({ id: 'feature' }));
        expect(result.current.error).toBe(failure);
    });

    it.each([RefTypeTag, RefTypeCommit])('preserves the %s fallback for a shared reference', async (type) => {
        mocks.router.query = { ref: 'revision', compare: 'revision' };
        branches.get.mockRejectedValue(new NotFoundError('branch not found'));
        if (type === RefTypeTag) tags.get.mockResolvedValue({ id: 'revision' });
        else commits.get.mockResolvedValue({ id: 'revision' });
        const { result } = renderHook(useRefs, { wrapper });

        await waitFor(() => expect(result.current.loading).toBe(false));
        expect(result.current.error).toBeNull();
        expect(result.current.reference).toEqual({ id: 'revision', type });
        expect(result.current.compare).toEqual({ id: 'revision', type });
        expect(branches.get).toHaveBeenCalledTimes(1);
        expect(branches.list).toHaveBeenCalledExactlyOnceWith('repo', true, '', '', 1);
        expect(tags.get).toHaveBeenCalledExactlyOnceWith('repo', 'revision');
        expect(commits.get).toHaveBeenCalledTimes(type === RefTypeCommit ? 1 : 0);
    });

    it('preserves the bare repository error', async () => {
        branches.get.mockRejectedValue(new NotFoundError('branch not found'));
        branches.list.mockResolvedValue({ results: [] });
        const { result } = renderHook(useRefs, { wrapper });

        await waitFor(() => expect(result.current.loading).toBe(false));
        expect(result.current.error).toBeInstanceOf(BareRepositoryError);
        expect(result.current.reference).toBeNull();
        expect(result.current.compare).toBeNull();
        expect(tags.get).not.toHaveBeenCalled();
        expect(commits.get).not.toHaveBeenCalled();
    });
});
