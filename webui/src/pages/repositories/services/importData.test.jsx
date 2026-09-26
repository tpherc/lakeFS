import React, { useRef, useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, test, vi } from 'vitest';
import { ImportForm, startImport } from './importData';
import { imports } from '../../../lib/api';

const storages = [
    {
        blockstore_id: 'home',
        import_support: true,
        import_validity_regex: '^s3://',
        blockstore_namespace_example: 's3://bucket/',
    },
    {
        blockstore_id: 'source',
        import_support: true,
        import_validity_regex: '^gs://',
        blockstore_namespace_example: 'gs://bucket/',
    },
    { blockstore_id: 'unsupported', import_support: false },
];

test('changing import backend revalidates the existing URI and submits its binding', async () => {
    const create = vi.spyOn(imports, 'create').mockResolvedValue({ id: 'import' });
    const user = userEvent.setup();
    const Wrapper = () => {
        const [storageID, setStorageID] = useState('');
        const [valid, setValid] = useState(false);
        const sourceRef = useRef(null);
        return (
            <>
                <ImportForm
                    config={storages.find((storage) => storage.blockstore_id === (storageID || 'home'))}
                    storageConfigs={storages}
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
    render(<Wrapper />);
    await user.type(screen.getByPlaceholderText('s3://bucket/'), 'gs://raw/prefix/');
    expect(screen.getByRole('button', { name: 'Start' })).toBeDisabled();
    await user.selectOptions(screen.getByLabelText('Source backend'), 'source');
    expect(screen.getByRole('button', { name: 'Start' })).toBeEnabled();
    expect(screen.getByRole('option', { name: 'unsupported' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Start' }));
    expect(create).toHaveBeenCalledWith('repo', 'main', 'gs://raw/prefix/', '', 'Import', {}, 'source');
    create.mockRestore();
});
