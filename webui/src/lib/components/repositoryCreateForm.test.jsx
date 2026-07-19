import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, test, vi } from 'vitest';

import { RepositoryCreateForm } from './repositoryCreateForm';

const storageConfig = (id, warning) => ({
    blockstore_id: id,
    blockstore_description: id,
    blockstore_namespace_ValidityRegex: '^mem://',
    blockstore_namespace_example: `mem://${id}`,
    blockstore_type: 'mem',
    default_namespace_prefix: null,
    warnings: [warning],
});

test('repository create form submits selected storage backend and warning', async () => {
    const user = userEvent.setup();
    const onSubmit = vi.fn();

    const Wrapper = () => {
        const [formValid, setFormValid] = useState(true);
        return (
            <RepositoryCreateForm
                formID="repository-create-form"
                configs={[storageConfig('alpha', 'alpha warning'), storageConfig('beta', 'beta warning')]}
                formValid={formValid}
                setFormValid={setFormValid}
                onSubmit={onSubmit}
            />
        );
    };

    const { container } = render(<Wrapper />);

    const storageSelect = screen.getByLabelText('Storage Backend');
    expect(storageSelect).toBeInTheDocument();
    expect(screen.getByText('alpha warning')).toBeInTheDocument();

    await user.selectOptions(storageSelect, 'beta');
    expect(screen.queryByText('alpha warning')).not.toBeInTheDocument();
    expect(screen.getByText('beta warning')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Repository ID'), 'repo1');
    await user.type(screen.getByLabelText('Storage Namespace'), 'mem://repo1');
    fireEvent.submit(container.querySelector('form'));

    await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledWith({
            name: 'repo1',
            storage_id: 'beta',
            storage_namespace: 'mem://repo1',
            default_branch: 'main',
            sample_data: false,
        });
    });
});
