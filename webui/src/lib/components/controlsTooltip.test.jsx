import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ClipboardButton, PrefixSearchWidget, TooltipButton } from './controls';

describe('button tooltip positioning', () => {
    afterEach(() => vi.restoreAllMocks());

    it.each([
        ['tooltip button', <TooltipButton tooltip="Expand changes">Expand</TooltipButton>],
        ['clipboard button', <ClipboardButton text="commit-id" tooltip="Copy commit" aria-label="Copy" />],
        ['prefix search button', <PrefixSearchWidget onFilter={vi.fn()} />],
    ])('keeps the %s outside document flow before and after positioning', async (_name, control) => {
        const initialStyles = [];
        const appendChild = document.body.appendChild.bind(document.body);
        // Capture portal insertion before Popper's measuring effects can change its styles.
        vi.spyOn(document.body, 'appendChild').mockImplementation((node) => {
            if (node.getAttribute?.('role') === 'tooltip') {
                initialStyles.push({ position: node.style.position, opacity: node.style.opacity });
            }
            return appendChild(node);
        });
        render(control);

        fireEvent.mouseOver(screen.getByRole('button'));
        const tooltip = await screen.findByRole('tooltip');
        expect(initialStyles).toHaveLength(1);
        expect(initialStyles[0].position).toBe('fixed');
        expect(initialStyles[0].opacity).toBe('0');

        await waitFor(() => {
            expect(tooltip.style.position).toBe(initialStyles[0].position);
            expect(tooltip.style.transform).not.toBe('');
            expect(tooltip.style.opacity).toBe('');
        });
        fireEvent.mouseOut(screen.getByRole('button'));
        await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
    });

    it('expands prefix search, submits the entered prefix, and collapses again', () => {
        const onFilter = vi.fn();
        render(<PrefixSearchWidget onFilter={onFilter} />);
        const searchButton = screen.getByRole('button');
        expect(searchButton).not.toHaveClass('btn-sm');

        fireEvent.click(searchButton);
        const input = screen.getByRole('textbox', { name: 'Search by Prefix' });
        fireEvent.change(input, { target: { value: 'reports/2026/' } });
        fireEvent.submit(input.closest('form'));
        expect(onFilter).toHaveBeenCalledExactlyOnceWith('reports/2026/');

        fireEvent.click(screen.getByRole('button'));
        expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    });

    it('shows the tooltip on keyboard focus and hides it on blur', async () => {
        render(<TooltipButton tooltip="Expand changes">Expand</TooltipButton>);
        const button = screen.getByRole('button', { name: 'Expand' });

        fireEvent.focus(button);
        expect(await screen.findByRole('tooltip')).toHaveTextContent('Expand changes');

        fireEvent.blur(button);
        await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
    });
});
