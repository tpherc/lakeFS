import React from 'react';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { commits, objects } from '../../api';
import * as apiHooks from '../../hooks/api';
import { RefTypeBranch } from '../../../constants';
import { Tree } from './tree';

dayjs.extend(relativeTime);

vi.mock('../../auth/authContext', () => ({
    useAuth: () => ({ onUnauthenticated: vi.fn() }),
}));

vi.mock('../../hooks/configProvider', () => ({
    useConfigContext: () => ({
        config: { storages: [{ blockstore_id: 'home', pre_sign_support: true, pre_sign_support_ui: true }] },
    }),
}));

const object = {
    path: 'report.txt',
    path_type: 'object',
    size_bytes: 12,
    mtime: 1_700_000_000,
    checksum: 'checksum',
    physical_address: 's3://bucket/report',
    metadata: { team: 'research' },
};
const prefix = { path: 'reports/', path_type: 'common_prefix' };

const renderTree = (results = [object], onDelete = vi.fn()) =>
    render(
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <Tree
                repo={{ id: 'example', storage_id: 'home' }}
                reference={{ id: 'main', type: RefTypeBranch }}
                results={results}
                onDelete={onDelete}
                showActions
            />
        </MemoryRouter>,
    );

const openAction = async (user, path, action) => {
    const row = screen.getByRole('link', { name: path }).closest('tr');
    const toggle = within(row).getByRole('button', { expanded: false });
    await user.click(toggle);
    await user.click(within(row).getByText(action));
    return toggle;
};

const closeDialog = async (user, dialog) => {
    await user.click(within(dialog).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
};

describe('object row dialogs', () => {
    beforeEach(() => {
        vi.spyOn(commits, 'blame');
        vi.spyOn(objects, 'listAll');
    });
    afterEach(() => vi.restoreAllMocks());

    it('does not initialize hidden API hooks when rendering object and directory rows', async () => {
        const useAPI = vi.spyOn(apiHooks, 'useAPI');
        renderTree([object, { ...object, path: 'other.txt' }, prefix]);
        await act(async () => {});

        expect(screen.getByRole('link', { name: 'report.txt' })).toBeInTheDocument();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(useAPI).not.toHaveBeenCalled();
        expect(commits.blame).not.toHaveBeenCalled();
        expect(objects.listAll).not.toHaveBeenCalled();
    });

    it('opens object info, finishes closing, restores focus, and reopens', async () => {
        const user = userEvent.setup();
        renderTree();
        const toggle = await openAction(user, object.path, 'Object Info');
        const dialog = await screen.findByRole('dialog');
        expect(dialog).toHaveTextContent('Object Information');
        expect(dialog).toHaveTextContent(object.physical_address);
        expect(dialog).toHaveTextContent('research');
        expect(commits.blame).not.toHaveBeenCalled();
        expect(objects.listAll).not.toHaveBeenCalled();

        await closeDialog(user, dialog);
        expect(toggle).toHaveFocus();
        expect(document.body).not.toHaveClass('modal-open');
        await openAction(user, object.path, 'Object Info');
        expect(await screen.findByRole('dialog')).toHaveTextContent(object.path);
    });

    it('opens another row after closing object info without retaining the previous row data', async () => {
        const user = userEvent.setup();
        const other = {
            ...object,
            path: 'other.txt',
            physical_address: 's3://bucket/other',
            metadata: { team: 'operations' },
        };
        renderTree([object, other]);
        const firstToggle = await openAction(user, object.path, 'Object Info');
        const firstDialog = await screen.findByRole('dialog');
        expect(firstDialog).toHaveTextContent(object.physical_address);
        expect(firstDialog).toHaveTextContent('research');

        await closeDialog(user, firstDialog);
        await waitFor(() => expect(firstDialog).not.toBeInTheDocument());
        expect(firstToggle).toHaveFocus();
        expect(document.body).not.toHaveClass('modal-open');

        const secondToggle = await openAction(user, other.path, 'Object Info');
        const secondDialog = await screen.findByRole('dialog');
        expect(screen.getAllByRole('dialog', { hidden: true })).toHaveLength(1);
        expect(secondDialog).toHaveTextContent(other.path);
        expect(secondDialog).toHaveTextContent(other.physical_address);
        expect(secondDialog).toHaveTextContent('operations');
        expect(secondDialog).not.toHaveTextContent(object.path);
        expect(secondDialog).not.toHaveTextContent(object.physical_address);
        expect(secondDialog).not.toHaveTextContent('research');

        await closeDialog(user, secondDialog);
        await waitFor(() => expect(secondDialog).not.toBeInTheDocument());
        expect(secondToggle).toHaveFocus();
        expect(document.body).not.toHaveClass('modal-open');
    });

    it('loads blame on demand, displays errors, and fetches again after reopening', async () => {
        const user = userEvent.setup();
        let rejectBlame;
        commits.blame.mockReturnValueOnce(
            new Promise((_resolve, reject) => {
                rejectBlame = reject;
            }),
        );
        commits.blame.mockResolvedValueOnce({
            id: 'commit-id',
            message: 'Updated report',
            committer: 'tester',
            creation_date: 1_700_000_000,
        });
        renderTree();
        expect(commits.blame).not.toHaveBeenCalled();
        await openAction(user, object.path, 'Blame');
        const dialog = await screen.findByRole('dialog');
        expect(dialog).toHaveTextContent('Loading...');
        expect(commits.blame).toHaveBeenCalledExactlyOnceWith('example', 'main', object.path, 'object');
        await act(async () => rejectBlame(new Error('Blame unavailable')));
        expect(await within(dialog).findByRole('alert')).toHaveTextContent('Blame unavailable');

        await closeDialog(user, dialog);
        await openAction(user, object.path, 'Blame');
        expect(await screen.findByText('Updated report')).toBeInTheDocument();
        expect(commits.blame).toHaveBeenCalledTimes(2);
        expect(objects.listAll).not.toHaveBeenCalled();
    });

    it('calculates directory size only after opening and consumes all pages', async () => {
        const user = userEvent.setup();
        const next = vi
            .fn()
            .mockResolvedValueOnce({ page: [{ size_bytes: 12 }], done: false })
            .mockResolvedValueOnce({ page: [{ size_bytes: 8 }], done: true });
        objects.listAll.mockReturnValue({ next });
        renderTree([prefix]);
        expect(objects.listAll).not.toHaveBeenCalled();
        await openAction(user, prefix.path, 'Calculate Size');
        const dialog = await screen.findByRole('dialog');
        expect(await within(dialog).findByText('20 Bytes (20.0 B)')).toBeInTheDocument();
        expect(within(dialog).getByText('2')).toBeInTheDocument();
        expect(objects.listAll).toHaveBeenCalledExactlyOnceWith('example', 'main', prefix.path);
        expect(next).toHaveBeenCalledTimes(2);
        expect(commits.blame).not.toHaveBeenCalled();
        await closeDialog(user, dialog);
    });

    it('cancels deletion and confirms exactly once for the selected row', async () => {
        const user = userEvent.setup();
        const onDelete = vi.fn();
        renderTree([object, { ...object, path: 'other.txt' }], onDelete);
        await openAction(user, object.path, 'Delete');
        let dialog = await screen.findByRole('dialog');
        expect(dialog).toHaveTextContent(`delete object "${object.path}"`);
        await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
        expect(onDelete).not.toHaveBeenCalled();

        await openAction(user, object.path, 'Delete');
        dialog = await screen.findByRole('dialog');
        await user.click(within(dialog).getByRole('button', { name: 'Yes' }));
        expect(onDelete).toHaveBeenCalledExactlyOnceWith(object);
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    });
});
