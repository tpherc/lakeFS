import React from 'react';
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import { RefTypeBranch } from '../../../constants';
import { URINavigator } from './tree';

describe('URINavigator actions', () => {
    it('groups the download action with the other outlined actions', () => {
        render(
            <MemoryRouter>
                <URINavigator
                    repo={{ id: 'example' }}
                    reference={{ id: 'main', type: RefTypeBranch }}
                    path="reports/result.csv"
                    downloadUrl="/api/v1/repositories/example/refs/main/objects?path=reports/result.csv"
                    isPathToFile
                    hasCopyButton
                />
            </MemoryRouter>,
        );

        const download = screen.getByRole('button', { name: 'Download object' });
        const actionGroup = download.closest('.btn-group');

        expect(download).toHaveClass('btn', 'btn-outline-secondary', 'btn-sm', 'download-button');
        expect(download).toHaveAttribute('download', 'result.csv');
        expect(actionGroup).toHaveClass('btn-group');
        expect(actionGroup.querySelectorAll('.btn')).toHaveLength(2);
    });
});
