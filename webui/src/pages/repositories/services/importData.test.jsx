import React, { useRef, useState } from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, test, vi } from 'vitest';
import { ImportForm, startImport } from './importData';
import { imports } from '../../../lib/api';

const storages = [
    {
        blockstore_id: 'source',
        blockstore_description: 'Secondary',
        import_support: true,
        import_validity_regex: '^gs://',
        blockstore_namespace_example: 'gs://bucket/',
    },
    {
        blockstore_id: 'home',
        blockstore_description: 'Primary',
        import_support: true,
        import_validity_regex: '^s3://',
        blockstore_namespace_example: 's3://bucket/',
    },
    { blockstore_id: 'unsupported', import_support: false },
];

const ImportWrapper = ({ storageConfigs = storages, repositoryStorageID = 'home' }) => {
    const [storageID, setStorageID] = useState('');
    const [valid, setValid] = useState(false);
    const sourceRef = useRef(null);
    const config = storageConfigs.find((storage) => storage.blockstore_id === (storageID || repositoryStorageID));
    return (
        <>
            <ImportForm
                config={config}
                storageConfigs={storageConfigs}
                repositoryStorageID={repositoryStorageID}
                sourceStorageID={storageID}
                onSourceStorageChange={setStorageID}
                sourceRef={sourceRef}
                destRef={useRef(null)}
                commitMsgRef={useRef(null)}
                repo="repo"
                branch="main"
                metadataFields={[]}
                setMetadataFields={() => {}}
                updateSrcValidity={setValid}
            />
            <button
                disabled={!valid}
                onClick={() =>
                    startImport(
                        () => {},
                        '',
                        'Import',
                        sourceRef.current.value,
                        'repo',
                        'main',
                        {},
                        storageID || undefined,
                    )
                }
            >
                Start
            </button>
        </>
    );
};

afterEach(() => vi.restoreAllMocks());

test('each backend appears once and the repository backend is selected even when it is not first', () => {
    render(<ImportWrapper />);
    const select = screen.getByLabelText('Source backend');
    expect(select).toHaveValue('');
    expect(
        within(select)
            .getAllByRole('option')
            .map((option) => option.textContent),
    ).toEqual(['Secondary · source', 'Primary · home', 'unsupported']);
    expect(screen.getByRole('option', { name: 'Primary · home' }).selected).toBe(true);
    expect(screen.getByRole('option', { name: 'unsupported' })).toBeDisabled();
    expect(screen.queryByRole('option', { name: 'Repository backend' })).not.toBeInTheDocument();
    expect(screen.getByText('Repository default')).toHaveClass('badge');
    expect(select).not.toContainElement(screen.getByText('Repository default'));
});

test('switching source and back to home revalidates the URI and preserves each API binding', async () => {
    const create = vi.spyOn(imports, 'create').mockResolvedValue({ id: 'import' });
    const user = userEvent.setup();
    render(<ImportWrapper />);
    const source = screen.getByPlaceholderText('s3://bucket/');
    const select = screen.getByLabelText('Source backend');
    const start = screen.getByRole('button', { name: 'Start' });
    await user.type(source, 'gs://raw/prefix/');
    expect(start).toBeDisabled();
    await user.selectOptions(select, 'source');
    expect(start).toBeEnabled();
    expect(screen.queryByText('Repository default')).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Primary · home' })).toHaveValue('');
    await user.click(start);
    expect(create).toHaveBeenLastCalledWith('repo', 'main', 'gs://raw/prefix/', '', 'Import', {}, 'source');
    await user.selectOptions(select, '');
    expect(start).toBeDisabled();
    expect(screen.getByText('Repository default')).toHaveClass('badge');
    await user.clear(source);
    await user.type(source, 's3://raw/prefix/');
    expect(start).toBeEnabled();
    await user.click(start);
    expect(create).toHaveBeenLastCalledWith('repo', 'main', 's3://raw/prefix/', '', 'Import', {}, undefined);
});

test('an unsupported repository backend stays disabled without selecting a different backend', () => {
    render(<ImportWrapper repositoryStorageID="unsupported" />);
    const home = screen.getByRole('option', { name: 'unsupported' });
    expect(home).toBeDisabled();
    expect(home.selected).toBe(true);
    expect(screen.getByLabelText('Source backend')).toHaveValue('');
    expect(screen.getByText('Repository default')).toHaveClass('badge');
    expect(screen.getByRole('button', { name: 'Start' })).toBeDisabled();
});

test('a missing repository backend requires an explicit supported selection', async () => {
    const user = userEvent.setup();
    render(<ImportWrapper repositoryStorageID="missing" />);
    const select = screen.getByLabelText('Source backend');
    const placeholder = screen.getByRole('option', { name: 'Choose source backend' });
    expect(placeholder).toBeDisabled();
    expect(placeholder.selected).toBe(true);
    expect(select).toHaveValue('');
    expect(screen.queryByText('Repository default')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start' })).toBeDisabled();
    await user.selectOptions(select, 'source');
    await user.type(screen.getByPlaceholderText('gs://bucket/'), 'gs://raw/prefix/');
    expect(screen.getByRole('button', { name: 'Start' })).toBeEnabled();
});

test('a single legacy backend needs no selector and retains the implicit API binding', async () => {
    const create = vi.spyOn(imports, 'create').mockResolvedValue({ id: 'import' });
    const user = userEvent.setup();
    const legacy = { ...storages[1], blockstore_id: '' };
    render(<ImportWrapper storageConfigs={[legacy]} repositoryStorageID="" />);
    expect(screen.queryByLabelText('Source backend')).not.toBeInTheDocument();
    expect(screen.queryByText('Repository default')).not.toBeInTheDocument();
    await user.type(screen.getByPlaceholderText('s3://bucket/'), 's3://raw/prefix/');
    await user.click(screen.getByRole('button', { name: 'Start' }));
    expect(create).toHaveBeenCalledWith('repo', 'main', 's3://raw/prefix/', '', 'Import', {}, undefined);
});
